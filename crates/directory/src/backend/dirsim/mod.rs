/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

//! A recipient directory backed by `lance-graph-dir-sim`.
//!
//! Stalwart resolves every inbound recipient through
//! [`Directory::recipient`](crate::Directory::recipient). The question is
//! about a **mailbox**: does mail to this address land somewhere? An
//! [`Recipient::Account`] answer is synchronised into Stalwart's own
//! registry (`synchronize_account`), which is what gives the recipient its
//! mailbox. Stalwart names the answer after its principal, but a directory
//! account and a mailbox are two things: an account can exist with no
//! mailbox (a departed user, disabled and no longer mail-enabled), and this
//! lookup answers only for the mailbox. It answers from one version of a
//! simulated directory:
//!
//! 1. The recipient text crosses into the directory once, as a `KeyId`
//!    (`Dicts::key_lookup`: normalised, counted, never minting).
//! 2. `validate::address_owner` decides on ids only: no holder, exactly
//!    one holder, or a conflict listing every holder.
//! 3. The holder must receive mail (`View::is_mail_recipient`, OGAR's
//!    recipient lifecycle). A holder that no longer does — a departed user
//!    whose stale `mail` still reserves the address — has no mailbox, so
//!    the address is no recipient. Its account is untouched: it is still in
//!    the directory, disabled, and a simulation still sees it there. A
//!    disabled shared mailbox is a mailbox and still receives.
//! 4. Only the answer is turned back into text: the owner's primary SMTP
//!    address becomes the account's address.
//!
//! A conflicting address is an error, not a guess: the message is not
//! delivered to any of the holders.
//!
//! The directory also answers what the owner *is*:
//!
//! - a group's address is a [`Recipient::Group`], never an account: a group
//!   has no mailbox and no credentials of its own;
//! - an account carries its groups ([`Account::groups`]) as their primary
//!   SMTP addresses, the same shape the LDAP backend produces. Stalwart
//!   synchronises them into the account's group membership, which is where
//!   its roles and permissions attach. The list is the directory's whole
//!   answer (`Some`, possibly empty), so a membership the directory dropped
//!   is dropped from the account as well. A group without a primary SMTP
//!   address cannot be named in Stalwart and is left out.

use crate::{Account, Credentials, Group, Recipient};
use lance_graph_dir_sim::validate::address_owner;
use lance_graph_dir_sim::{GroupOrdinal, VersionStore, View};
use ogar_dir_core::Guid128;
use ogar_dir_sim::{Attribute, VersionId, Violation};

pub struct DirSimDirectory {
    store: VersionStore,
    version: VersionId,
}

impl DirSimDirectory {
    /// Serve recipients from `version` of `store`. Fails if the version
    /// does not exist, so a misconfigured directory is caught at startup
    /// rather than at the first recipient.
    pub fn new(store: VersionStore, version: VersionId) -> Result<Self, String> {
        store
            .view(version)
            .map_err(|err| format!("dir-sim version {version:?}: {err:?}"))?;
        Ok(Self { store, version })
    }

    fn view(&self) -> trc::Result<View<'_>> {
        self.store.view(self.version).map_err(|err| {
            trc::StoreEvent::UnexpectedError
                .into_err()
                .details("dir-sim version is no longer readable")
                .reason(format!("{err:?}"))
        })
    }

    /// The directory has no credentials; it only resolves recipients.
    pub async fn authenticate(&self, _credentials: &Credentials) -> trc::Result<Account> {
        Err(trc::AuthEvent::Error
            .into_err()
            .details("dir-sim directories do not authenticate"))
    }

    pub async fn recipient(&self, address: &str) -> trc::Result<Recipient> {
        let Some(key) = self.store.dicts().key_lookup(address) else {
            return Ok(Recipient::Invalid);
        };
        let view = self.view()?;
        match address_owner(&view, key) {
            Ok(None) => Ok(Recipient::Invalid),
            // Held, but by an object with no mailbox (a departed user's
            // stale `mail`): the address stays reserved and nothing receives
            // at it. The object's account is the directory's, not this
            // lookup's, and is not affected.
            Ok(Some(holder)) if !view.is_mail_recipient(&holder) => Ok(Recipient::Invalid),
            Ok(Some(owner)) => self.account(&view, owner, address),
            Err(Violation::AddressConflict { holders, .. }) => Err(trc::StoreEvent::DataCorruption
                .into_err()
                .details("Recipient address is held by more than one directory object")
                .ctx(trc::Key::To, address.to_string())
                .reason(format!("{holders:?}"))),
            Err(other) => Err(trc::StoreEvent::UnexpectedError
                .into_err()
                .details("Unexpected directory violation")
                .reason(format!("{other:?}"))),
        }
    }

    /// Text egress: the owner's primary SMTP address names the account.
    /// The address that was asked for is an alias when it differs, because
    /// the directory has just proved the owner holds it.
    fn account(&self, view: &View<'_>, owner: Guid128, address: &str) -> trc::Result<Recipient> {
        let Some(email) = view
            .attr(&owner, Attribute::PrimarySmtp)
            .and_then(|value| self.store.value(value))
            .and_then(utils::sanitize_email)
        else {
            // An owner without a primary SMTP address has no mailbox.
            return Ok(Recipient::Invalid);
        };
        let email_aliases = utils::sanitize_email(address)
            .filter(|alias| *alias != email)
            .into_iter()
            .collect();
        if view.group_ordinal(&owner).is_some() {
            return Ok(Recipient::Group(Group {
                email,
                email_aliases,
                description: None,
            }));
        }
        Ok(Recipient::Account(Account {
            email,
            email_aliases,
            groups: Some(self.groups_of(view, &owner)),
            ..Default::default()
        }))
    }

    /// The primary SMTP addresses of the groups `user` is a member of, in
    /// group order.
    fn groups_of(&self, view: &View<'_>, user: &Guid128) -> Vec<String> {
        (0..view.groups_len())
            .filter_map(|i| view.group_guid(GroupOrdinal(u16::try_from(i).ok()?)))
            .filter(|group| view.exists(group) && view.is_member(user, group))
            .filter_map(|group| {
                view.attr(&group, Attribute::PrimarySmtp)
                    .and_then(|value| self.store.value(value))
                    .and_then(utils::sanitize_email)
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lance_graph_dir_sim::{Observation, ObservedNode, ObservedRecipient};
    use ogar_dir_core::DirectoryScope;

    const SCOPE: DirectoryScope = DirectoryScope(Guid128([0x5C; 16]));
    const ROUTING: &str = "a@tenant.mail.onmicrosoft.com";

    fn g(n: u8) -> Guid128 {
        Guid128([n; 16])
    }

    /// User A: primary SMTP `a@example.org`, a remote mailbox routing to
    /// `ROUTING`, which A also holds as a proxy address.
    fn user_a() -> ObservedNode {
        let mut u = ObservedNode::user("a.upn@example.org", "a@example.org");
        u.mail = Some("a@example.org".into());
        u.alias = Some("a".into());
        u.proxies = vec![format!("smtp:{ROUTING}")];
        u.recipient = Some(ObservedRecipient {
            remote_recipient_type: Some(4),
            display_type: Some(-2_147_483_642),
            type_details: Some(2_147_483_648),
            target_address: Some(ROUTING.into()),
        });
        u
    }

    fn directory(nodes: Vec<(Guid128, ObservedNode)>) -> DirSimDirectory {
        directory_with(nodes, vec![])
    }

    fn directory_with(
        nodes: Vec<(Guid128, ObservedNode)>,
        members: Vec<(Guid128, Guid128)>,
    ) -> DirSimDirectory {
        let mut store = VersionStore::new();
        let version = store
            .observe(
                "lab",
                0,
                Observation {
                    scope: SCOPE,
                    nodes,
                    members,
                },
            )
            .unwrap();
        DirSimDirectory::new(store, version).unwrap()
    }

    fn account(email: &str, aliases: &[&str]) -> Recipient {
        Recipient::Account(Account {
            email: email.into(),
            email_aliases: aliases.iter().map(|a| a.to_string()).collect(),
            groups: Some(vec![]),
            ..Default::default()
        })
    }

    fn group(smtp: Option<&str>) -> ObservedNode {
        let mut g = ObservedNode::group();
        g.primary_smtp = smtp.map(Into::into);
        g
    }

    // The account carries the groups the directory says it is in, by their
    // primary SMTP address; a non-member group and an address-less group are
    // not listed.
    #[tokio::test]
    async fn an_account_carries_its_groups() {
        let dir = directory_with(
            vec![
                (g(0xA1), user_a()),
                (g(0x61), group(Some("sales@example.org"))),
                (g(0x62), group(Some("legal@example.org"))),
                (g(0x63), group(None)),
            ],
            vec![(g(0xA1), g(0x61)), (g(0xA1), g(0x63))],
        );
        let Recipient::Account(acct) = dir.recipient("a@example.org").await.unwrap() else {
            panic!("expected an account");
        };
        assert_eq!(acct.groups, Some(vec!["sales@example.org".to_string()]));
    }

    // A group's address names a group, not an account: no mailbox, no
    // credentials.
    #[tokio::test]
    async fn a_group_address_is_a_group_not_an_account() {
        let dir = directory(vec![(g(0x61), group(Some("sales@example.org")))]);
        assert_eq!(
            dir.recipient("sales@example.org").await.unwrap(),
            Recipient::Group(Group {
                email: "sales@example.org".into(),
                ..Default::default()
            })
        );
    }

    #[tokio::test]
    async fn a_recipient_gets_the_owners_mailbox() {
        let dir = directory(vec![(g(0xA1), user_a())]);
        assert_eq!(
            dir.recipient("a@example.org").await.unwrap(),
            account("a@example.org", &[])
        );
        // Casing and whitespace do not change the identity.
        assert_eq!(
            dir.recipient(" A@Example.ORG ").await.unwrap(),
            account("a@example.org", &[])
        );
    }

    #[tokio::test]
    async fn another_held_address_lands_in_the_same_mailbox() {
        let dir = directory(vec![(g(0xA1), user_a())]);
        assert_eq!(
            dir.recipient(ROUTING).await.unwrap(),
            account("a@example.org", &[ROUTING])
        );
    }

    #[tokio::test]
    async fn two_users_get_two_mailboxes() {
        let dir = directory(vec![
            (g(0xA1), user_a()),
            (
                g(0xB0),
                ObservedNode::user("b.upn@example.org", "b@example.org"),
            ),
        ]);
        assert_eq!(
            dir.recipient("b@example.org").await.unwrap(),
            account("b@example.org", &[])
        );
        assert_eq!(
            dir.recipient("a@example.org").await.unwrap(),
            account("a@example.org", &[])
        );
    }

    #[tokio::test]
    async fn an_unknown_address_has_no_mailbox() {
        let dir = directory(vec![(g(0xA1), user_a())]);
        assert_eq!(
            dir.recipient("nobody@example.org").await.unwrap(),
            Recipient::Invalid
        );
    }

    #[tokio::test]
    async fn a_contested_address_is_refused_not_guessed() {
        let mut b = ObservedNode::user("b.upn@example.org", "b@example.org");
        b.mail = Some("a@example.org".into());
        let dir = directory(vec![(g(0xA1), user_a()), (g(0xB0), b)]);
        let err = dir.recipient("a@example.org").await.unwrap_err();
        assert_eq!(
            err.as_ref(),
            &trc::EventType::Store(trc::StoreEvent::DataCorruption)
        );
        // The uncontested address of B still resolves.
        assert_eq!(
            dir.recipient("b@example.org").await.unwrap(),
            account("b@example.org", &[])
        );
    }

    /// D-IAM-IDENTITY-0: a departed user (disabled, not mail-enabled) whose
    /// `mail` and primary SMTP are still set.
    #[tokio::test]
    async fn a_departed_user_gets_no_mailbox() {
        let mut d = ObservedNode::user("d.upn@example.org", "d@example.org");
        d.active = Some(false);
        d.mail = Some("d@example.org".into());
        d.recipient = Some(ObservedRecipient::default());
        let dir = directory(vec![(g(0xDD), d)]);
        assert_eq!(
            dir.recipient("d@example.org").await.unwrap(),
            Recipient::Invalid
        );
    }

    /// A disabled shared mailbox is still a recipient.
    #[tokio::test]
    async fn a_disabled_shared_mailbox_gets_an_account() {
        let mut s = ObservedNode::user("s.upn@example.org", "shared@example.org");
        s.active = Some(false);
        s.mail = Some("shared@example.org".into());
        s.alias = Some("shared".into());
        s.proxies = vec!["smtp:shared@tenant.mail.onmicrosoft.com".into()];
        s.recipient = Some(ObservedRecipient {
            remote_recipient_type: Some(97),
            display_type: Some(-2_147_483_642),
            type_details: Some(34_359_738_368),
            target_address: Some("shared@tenant.mail.onmicrosoft.com".into()),
        });
        let dir = directory(vec![(g(0x5A), s)]);
        assert_eq!(
            dir.recipient("shared@example.org").await.unwrap(),
            account("shared@example.org", &[])
        );
    }

    #[tokio::test]
    async fn a_missing_version_is_rejected_at_construction() {
        let store = VersionStore::new();
        assert!(DirSimDirectory::new(store, VersionId(42)).is_err());
    }
}
