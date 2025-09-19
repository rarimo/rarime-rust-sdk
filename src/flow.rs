use crate::RarimeError;
use crate::document::{DocumentStatus, RarimeDocument};

pub fn get_document_status(document: RarimeDocument) -> Result<DocumentStatus, RarimeError> {
    return Ok(DocumentStatus::REGISTRED_WITH_OTHER_PK);
}
