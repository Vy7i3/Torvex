#[derive(Debug, Clone)]
pub struct ScanResult {
    pub path: String,
    pub sha256: String,
    pub size: u64,
    pub file_type: Option<String>,
    pub status: Verdict,
    pub confidence: Option<f32>,
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Clean,
    Suspicious,
    Malicious,
}

impl std::fmt::Display for Verdict {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let label = match self {
            Self::Clean => "clean",
            Self::Suspicious => "suspicious",
            Self::Malicious => "malicious",
        };
        formatter.write_str(label)
    }
}
