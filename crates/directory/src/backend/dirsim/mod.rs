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
//! mailbox (a departed user, login disabled and mailbox deprovisioned), and this
//! lookup answers only for the mailbox. It answers from one version of a
//! simulated directory:
//!
//! 1. The recipient text crosses into the directory once, as a `KeyId`
//!    (`Dicts::key_lookup`: normalised, counted, never minting).
//! 2. `validate::address_owner` decides on ids only: no holder, exactly
//!    one holder, or a conflict listing every holder.
//! 3. The holder must receive mail (`View::is_mail_recipient`, OGAR's
//!    recipient lifecycle). `Disable-RemoteMailbox` clears the addresses
//!    with the mailbox, so a deprovisioned user's address normally has no
//!    holder at all (step 2). Mail addresses are provisioned by the
//!    recipient type, so an enabled account that is not mail-enabled holds
//!    its UPN but none of the SMTP values it still carries: those have no
//!    holder either. `mail` is a property on the user's business card,
//!    like the telephone number: shown in the address book and used inside
//!    messages, it follows the user rather than the mailbox; it is not the
//!    recipient's identity (immutably the mailbox's `ExchangeGuid`,
//!    implicitly its mutable `PrimarySmtpAddress`), not received at and
//!    not provisioned, and holds nothing. The guard covers the one holder that does not receive: with
//!    the cloud observed, a remote mailbox Exchange Online does not hold.
//!    The object's account is untouched: it
//!    stays in the directory. A disabled shared mailbox is a mailbox and
//!    still receives.
//!    With the cloud observed ([`DirSimDirectory::with_cloud`]), a remote
//!    mailbox also needs its Exchange Online mailbox, tied to the AD
//!    object by OGAR's hybrid correspondence fold on GUIDs. Without it, AD
//!    alone decides.
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
use lance_graph_dir_sim::{CloudMailboxes, GroupProperty, GroupWhere, VersionStore, View};
use ogar_dir_core::Guid128;
use ogar_dir_sim::{Attribute, VersionId, Violation};

pub struct DirSimDirectory {
    store: VersionStore,
    version: VersionId,
    /// The Exchange Online mailboxes, when the cloud was observed. `None`
    /// is "not observed" (AD alone decides), not "no mailboxes".
    cloud: Option<CloudMailboxes>,
}

impl DirSimDirectory {
    /// Serve recipients from `version` of `store`. Fails if the version
    /// does not exist, so a misconfigured directory is caught at startup
    /// rather than at the first recipient.
    pub fn new(store: VersionStore, version: VersionId) -> Result<Self, String> {
        store
            .view(version)
            .map_err(|err| format!("dir-sim version {version:?}: {err:?}"))?;
        Ok(Self {
            store,
            version,
            cloud: None,
        })
    }

    /// Decide remote mailboxes with the cloud observed: `cloud` comes from
    /// `CloudMailboxes::from_fold` over the AD, Entra and Exchange Online
    /// observations of this directory.
    pub fn with_cloud(mut self, cloud: CloudMailboxes) -> Self {
        self.cloud = Some(cloud);
        self
    }

    /// Whether mail to `node` is delivered to it in `view`.
    fn receives(&self, view: &View<'_>, node: &Guid128) -> bool {
        match &self.cloud {
            Some(cloud) => cloud.delivers_to(view, node),
            None => view.is_mail_recipient(node),
        }
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
            // Named, but the object has no mailbox (a remote mailbox missing
            // in Exchange Online): nothing receives at it. The object's account is the
            // directory's, not this lookup's.
            Ok(Some(holder)) if !self.receives(&view, &holder) => Ok(Recipient::Invalid),
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

    /// The primary SMTP addresses of the lists `user` receives mail
    /// through, in group order. Mail is chained addressing: a list reaches
    /// `user` directly or through nested lists, each by its own address, so
    /// a group without an address ends the chain.
    fn groups_of(&self, view: &View<'_>, user: &Guid128) -> Vec<String> {
        view.groups_transitive_through(user, &GroupWhere::Is(GroupProperty::MailEnabled))
            .into_iter()
            .filter(|group| view.exists(group))
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

    // Mail is chained addressing: A is in team, which is in legal, so A
    // carries both. A is also in an address-less group nested in board; that
    // group cannot be addressed, so the chain to board ends there.
    #[tokio::test]
    async fn an_account_carries_its_nested_groups() {
        let dir = directory_with(
            vec![
                (g(0xA1), user_a()),
                (g(0x61), group(Some("team@example.org"))),
                (g(0x62), group(Some("legal@example.org"))),
                (g(0x63), group(None)),
                (g(0x64), group(Some("board@example.org"))),
            ],
            vec![
                (g(0xA1), g(0x61)),
                (g(0x61), g(0x62)),
                (g(0xA1), g(0x63)),
                (g(0x63), g(0x64)),
            ],
        );
        let Recipient::Account(acct) = dir.recipient("a@example.org").await.unwrap() else {
            panic!("expected an account");
        };
        assert_eq!(
            acct.groups,
            Some(vec![
                "team@example.org".to_string(),
                "legal@example.org".to_string()
            ])
        );
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
        // A's primary SMTP address is B's UPN: two holders.
        let b = ObservedNode::user("a@example.org", "b@example.org");
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

    /// D-IAM-IDENTITY-0: a departed user after `Disable-RemoteMailbox` —
    /// login disabled, recipient attributes cleared except the deprovision
    /// bit (code 8). Nothing holds the address any more.
    #[tokio::test]
    async fn a_departed_user_gets_no_mailbox() {
        let mut d = ObservedNode::user("d.upn@example.org", "d@example.org");
        d.active = Some(false);
        d.primary_smtp = None;
        d.recipient = Some(ObservedRecipient {
            remote_recipient_type: Some(8),
            ..ObservedRecipient::default()
        });
        let dir = directory(vec![(g(0xDD), d)]);
        assert_eq!(
            dir.recipient("d@example.org").await.unwrap(),
            Recipient::Invalid
        );
    }

    /// An enabled account that is not mail-enabled gets no mailbox: its
    /// recipient type provisions none of the SMTP values it still carries,
    /// so `d@` has no holder.
    #[tokio::test]
    async fn an_enabled_account_without_a_mailbox_gets_no_mailbox() {
        let mut d = ObservedNode::user("d.upn@example.org", "d@example.org");
        d.active = Some(true);
        d.recipient = Some(ObservedRecipient::default());
        let dir = directory(vec![(g(0xDD), d)]);
        assert_eq!(
            dir.recipient("d@example.org").await.unwrap(),
            Recipient::Invalid
        );
    }

    /// `mail` is a business-card property of the user and may name another
    /// user's address: the user carrying it claims nothing by it, and the
    /// address names its real mailbox.
    #[tokio::test]
    async fn a_mail_label_on_another_user_claims_nothing() {
        let mut other = ObservedNode::user("o.upn@example.org", "o@example.org");
        other.mail = Some("shared@example.org".into());
        let mut s = ObservedNode::user("s.upn@example.org", "shared@example.org");
        s.mail = Some("shared@example.org".into());
        let dir = directory(vec![(g(0x01), other), (g(0x02), s)]);
        assert!(matches!(
            dir.recipient("shared@example.org").await.unwrap(),
            Recipient::Account(_)
        ));
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

    /// The fold over A (anchor + backsync to its Entra object), the Entra
    /// object, and `mailboxes` Exchange Online mailboxes for it.
    fn cloud(mailboxes: u8) -> CloudMailboxes {
        use ogar_dir_core::correspond::{IdColumn, Index, Lanes, Output, Rows, fold, state};
        let (a, anchor, entra) = (g(0xA1), g(0x0A), g(0x0E));
        let present = |c: &mut IdColumn, id: Guid128| {
            c.id.push(id);
            c.state.push(state::PRESENT);
        };
        let row = |r: &mut Rows, owner: Guid128| {
            r.owner.push(owner);
            r.scope.push(0);
            r.at.push(1_000);
        };
        let mut l = Lanes::default();
        row(&mut l.ad, a);
        present(&mut l.ad_anchor, anchor);
        present(&mut l.ad_backsync, entra);
        row(&mut l.entra, entra);
        present(&mut l.entra_anchor, anchor);
        for n in 0..mailboxes {
            row(&mut l.exo, g(0xE0 + n));
            present(&mut l.exo_external, entra);
        }
        let ix = Index::build(&l);
        let mut out = Output::for_index(&l, &ix);
        fold(&l, &ix, &mut out);
        CloudMailboxes::from_fold(&l, &ix, &out)
    }

    /// With the cloud observed, A's remote mailbox gets an account only
    /// when its Exchange Online mailbox exists.
    #[tokio::test]
    async fn a_remote_mailbox_needs_its_cloud_mailbox() {
        let with = directory(vec![(g(0xA1), user_a())]).with_cloud(cloud(1));
        assert_eq!(
            with.recipient("a@example.org").await.unwrap(),
            account("a@example.org", &[])
        );
        let without = directory(vec![(g(0xA1), user_a())]).with_cloud(cloud(0));
        assert_eq!(
            without.recipient("a@example.org").await.unwrap(),
            Recipient::Invalid
        );
        let ambiguous = directory(vec![(g(0xA1), user_a())]).with_cloud(cloud(2));
        assert_eq!(
            ambiguous.recipient("a@example.org").await.unwrap(),
            Recipient::Invalid
        );
    }

    /// Not observed is not observed empty: without the cloud, AD alone
    /// decides, as before.
    #[tokio::test]
    async fn without_the_cloud_ad_alone_decides() {
        let dir = directory(vec![(g(0xA1), user_a())]);
        assert_eq!(
            dir.recipient("a@example.org").await.unwrap(),
            account("a@example.org", &[])
        );
    }
}
