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
//! - a group's address is a [`Recipient::List`]: Stalwart delivers to its
//!   members, expanded here through nested lists, and creates no principal
//!   for it. A group has no mailbox and no credentials of its own, and
//!   being on a list gives a member neither the list's address to send as
//!   nor any grant (OGAR `DIRECTORY-SIMULATION-POC.md`, X13);
//! - an account carries its security groups ([`Account::groups`]) as their
//!   primary SMTP addresses, the same shape the LDAP backend produces.
//!   Stalwart synchronises them into the account's group membership, which
//!   is where its roles and permissions attach. They are the groups whose
//!   SID the account holds, through nested security groups. The list is
//!   the directory's whole answer (`Some`, possibly empty), so a membership
//!   the directory dropped is dropped from the account as well. A group
//!   without a primary SMTP address cannot be named in Stalwart and is left
//!   out.

use crate::{Account, Credentials, List, Recipient};
use lance_graph_dir_sim::validate::address_owner;
use lance_graph_dir_sim::{
    CloudMailboxes, GroupProperty, GroupWhere, VersionStore, View, receives_mail,
};
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

    /// Whether mail to `node` is delivered to it in `view`: dir-sim's one
    /// delivery rule, with the cloud when it was observed.
    fn receives(&self, view: &View<'_>, node: &Guid128) -> bool {
        receives_mail(view, self.cloud.as_ref(), node)
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
            return Ok(Recipient::List(List {
                email,
                email_aliases,
                members: self.list_members(view, &owner),
            }));
        }
        Ok(Recipient::Account(Account {
            email,
            email_aliases,
            groups: Some(self.groups_of(view, &owner)),
            ..Default::default()
        }))
    }

    /// Who mail to `group` is delivered to: the members the mail chain
    /// reaches (directly, or through nested lists by their own addresses),
    /// each that receives mail, by its primary SMTP address. Mail is chained
    /// addressing, never membership, so this is the whole of what a list
    /// does: its members get its mail, not its address or its grants.
    fn list_members(&self, view: &View<'_>, group: &Guid128) -> Vec<String> {
        view.members_transitive_through(group, &GroupWhere::Is(GroupProperty::MailEnabled))
            .into_iter()
            .filter(|member| self.receives(view, member))
            .filter_map(|member| self.primary_smtp(view, &member))
            .collect()
    }

    /// The groups whose ACL grants `user` holds in Stalwart: the security
    /// groups whose SID it holds, directly or through nested security
    /// groups, by their primary SMTP address (Stalwart names a group by its
    /// address, so a security group without one is not listed). A
    /// distribution list is mail, not membership, and is never listed: it
    /// would give the user its address to send as, and grants it does not
    /// carry.
    fn groups_of(&self, view: &View<'_>, user: &Guid128) -> Vec<String> {
        view.security_identifiers(user)
            .into_iter()
            .filter(|group| view.exists(group))
            .filter_map(|group| self.primary_smtp(view, &group))
            .collect()
    }

    fn primary_smtp(&self, view: &View<'_>, node: &Guid128) -> Option<String> {
        view.attr(node, Attribute::PrimarySmtp)
            .and_then(|value| self.store.value(value))
            .and_then(utils::sanitize_email)
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

    fn security_group(smtp: Option<&str>) -> ObservedNode {
        let mut g = group(smtp);
        g.security = Some(true);
        g
    }

    // A distribution list is mail, not membership (X13): being in one gives
    // the account neither the list's address nor its ACL grants, so it is
    // not among the account's groups. A security group is, by its address.
    #[tokio::test]
    async fn a_distribution_list_confers_no_group() {
        let dir = directory_with(
            vec![
                (g(0xA1), user_a()),
                (g(0x61), group(Some("sales@example.org"))),
                (g(0x62), security_group(Some("finance@example.org"))),
                (g(0x63), group(None)),
            ],
            vec![(g(0xA1), g(0x61)), (g(0xA1), g(0x62)), (g(0xA1), g(0x63))],
        );
        let Recipient::Account(acct) = dir.recipient("a@example.org").await.unwrap() else {
            panic!("expected an account");
        };
        assert_eq!(acct.groups, Some(vec!["finance@example.org".to_string()]));
    }

    // Mail to a list reaches its members, through nested lists by their own
    // addresses: legal contains team, which contains A and B. A list nested
    // through an address-less group is not reached (C), and a member that
    // does not receive mail (D, no mailbox) is not delivered to.
    #[tokio::test]
    async fn a_distribution_list_expands_to_its_members() {
        let mut d = ObservedNode::user("d.upn@example.org", "d@example.org");
        d.active = Some(true);
        d.recipient = Some(ObservedRecipient::default());
        let dir = directory_with(
            vec![
                (g(0xA1), user_a()),
                (
                    g(0xB0),
                    ObservedNode::user("b.upn@example.org", "b@example.org"),
                ),
                (
                    g(0xC0),
                    ObservedNode::user("c.upn@example.org", "c@example.org"),
                ),
                (g(0xDD), d),
                (g(0x61), group(Some("team@example.org"))),
                (g(0x62), group(Some("legal@example.org"))),
                (g(0x63), group(None)),
            ],
            vec![
                (g(0xA1), g(0x61)),
                (g(0xB0), g(0x61)),
                (g(0xDD), g(0x61)),
                (g(0x61), g(0x62)),
                (g(0xC0), g(0x63)),
                (g(0x63), g(0x62)),
            ],
        );
        assert_eq!(
            dir.recipient("legal@example.org").await.unwrap(),
            Recipient::List(List {
                email: "legal@example.org".into(),
                email_aliases: vec![],
                members: vec!["a@example.org".into(), "b@example.org".into()],
            })
        );
    }

    // Permissions follow the SID chain: a security group without an
    // address passes on the addressed security group it is nested in, so
    // Stalwart keeps that group's ACL grants. A distribution group without
    // an address has neither an address nor a SID and ends both chains.
    #[tokio::test]
    async fn an_account_keeps_the_groups_its_sid_chain_reaches() {
        let dir = directory_with(
            vec![
                (g(0xA1), user_a()),
                (g(0x71), security_group(None)),
                (g(0x72), security_group(Some("finance@example.org"))),
                (g(0x73), group(None)),
                (g(0x74), security_group(Some("hr@example.org"))),
            ],
            vec![
                (g(0xA1), g(0x71)),
                (g(0x71), g(0x72)),
                (g(0xA1), g(0x73)),
                (g(0x73), g(0x74)),
            ],
        );
        let Recipient::Account(acct) = dir.recipient("a@example.org").await.unwrap() else {
            panic!("expected an account");
        };
        assert_eq!(acct.groups, Some(vec!["finance@example.org".to_string()]));
    }

    // A group's address names a list to expand, never an account and never
    // a Stalwart group account: no mailbox, no credentials, and nothing a
    // member could send as.
    #[tokio::test]
    async fn a_group_address_is_a_list_not_an_account() {
        let dir = directory(vec![(g(0x61), group(Some("sales@example.org")))]);
        assert_eq!(
            dir.recipient("sales@example.org").await.unwrap(),
            Recipient::List(List {
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
