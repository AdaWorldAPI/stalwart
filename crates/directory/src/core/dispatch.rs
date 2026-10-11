/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{Account, Credentials, Directory, Recipient, backend::oidc::OidcDiscovery};
use registry::schema::enums::DirectoryType;
use trc::AddContext;

impl Directory {
    pub async fn authenticate(&self, credentials: &Credentials) -> trc::Result<Account> {
        match &self {
            Directory::Ldap(store) => store.authenticate(credentials).await,
            Directory::Sql(store) => store.authenticate(credentials).await,
            Directory::OpenId(store) => store.authenticate(credentials).await,
            #[cfg(feature = "dir-sim")]
            Directory::DirSim(store) => store.authenticate(credentials).await,
            Directory::Unavailable(directory) => Err(directory.error()),
        }
        .caused_by(trc::location!())
    }

    pub async fn recipient(&self, address: &str) -> trc::Result<Recipient> {
        match &self {
            Directory::Ldap(store) => store.recipient(address).await,
            Directory::Sql(store) => store.recipient(address).await,
            Directory::OpenId(_) => Ok(Recipient::Invalid), // OIDC directories do not support recipient lookups
            #[cfg(feature = "dir-sim")]
            Directory::DirSim(store) => store.recipient(address).await,
            Directory::Unavailable(directory) => Err(directory.error()),
        }
        .caused_by(trc::location!())
    }

    /// Whether a member of a group this directory serves may use the
    /// group's addresses as its own, i.e. send as the group by being a
    /// member of it. Stalwart's own groups work that way, and so do the
    /// LDAP and SQL directories it reads them from.
    ///
    /// A simulated Active Directory does not: membership in a security
    /// group carries its ACL grants, and sending as the group needs an
    /// explicit SendAs grant that membership is not (OGAR
    /// `DIRECTORY-SIMULATION-POC.md`, X13). The member keeps the group for
    /// its ACLs either way.
    pub fn members_send_as_group(&self) -> bool {
        match &self {
            #[cfg(feature = "dir-sim")]
            Directory::DirSim(_) => false,
            _ => true,
        }
    }

    pub fn has_bearer_token_support(&self) -> bool {
        match &self {
            Directory::OpenId(_) => true,
            Directory::Unavailable(directory) => directory.directory_type() == DirectoryType::Oidc,
            _ => false,
        }
    }

    pub fn can_lookup_recipients(&self) -> bool {
        match &self {
            Directory::OpenId(_) => false,
            Directory::Unavailable(directory) => directory.directory_type() != DirectoryType::Oidc,
            _ => true,
        }
    }

    pub fn oidc_discovery_document(&self) -> Option<&OidcDiscovery> {
        match &self {
            Directory::OpenId(directory) => Some(&directory.discovery),
            _ => None,
        }
    }
}
