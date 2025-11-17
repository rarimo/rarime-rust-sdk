use crate::VotingCriteria;
use api::types::ipfs_voting::OptionVariant;

#[derive(Debug, Clone)]
pub struct Question {
    pub title: String,
    pub description: Option<String>,
    pub variants: Vec<String>,
}

impl From<OptionVariant> for Question {
    fn from(ov: OptionVariant) -> Self {
        Question {
            title: ov.title,
            description: ov.description,
            variants: ov.variants,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ProposalData {
    pub poll_id: String,
    pub proposal_smt_address: String,
    pub criteria: VotingCriteria,
    pub status: u8,
    pub start_timestamp: u64,
    pub poll_duration: u64,
    pub image_cid: Option<String>,
    pub send_vote_contract_address: String,
    pub title: String,
    pub description: Option<String>,
    pub questions: Vec<Question>,
    pub ranking_based: Option<bool>,
    pub voting_results: Vec<Vec<String>>,
}
