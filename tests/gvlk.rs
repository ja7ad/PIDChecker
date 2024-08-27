//! Microsoft's published KMS client setup keys (GVLKs) must all decode, resolve
//! to the documented edition, and report the Volume:GVLK channel.

use std::path::Path;
use std::sync::Arc;

use pidkeychecker::config::Config;
use pidkeychecker::core::checker::{CheckOptions, Checker, KeyStatus};

const GVLKS: &[(&str, &str)] = &[
    ("W269N-WFGWX-YVC9B-4J6C9-T83GX", "Professional"),
    ("MH37W-N47XK-V7XM9-C7227-GCQG9", "ProfessionalN"),
    ("NRG8B-VKK3Q-CXVCJ-9G2XF-6Q84J", "ProfessionalWorkstation"),
    ("9FNHH-K3HBT-3W4TD-6383H-6XYWF", "ProfessionalWorkstationN"),
    ("6TP4R-GNPTD-KYYHQ-7B7DP-J447Y", "ProfessionalEducation"),
    ("YVWGF-BXNMC-HTQYQ-CPQ99-66QFC", "ProfessionalEducationN"),
    ("NW6C2-QMPVW-D7KKK-3GKT6-VCFB2", "Education"),
    ("2WH4N-8QGBV-H22JP-CT43Q-MDWWJ", "EducationN"),
    ("NPPR9-FWDCX-D2C8J-H872K-2YT43", "Enterprise"),
    ("DPH2V-TTNVB-4X9Q3-TJR4H-KHJW4", "EnterpriseN"),
    ("YYVX9-NTFWV-6MDM3-9PT4T-4M68B", "EnterpriseG"),
    ("44RPN-FTY23-9VTTB-MP9BX-T84FV", "EnterpriseGN"),
];

fn checker() -> Arc<Checker> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let dir = std::env::temp_dir().join(format!("pkc-it-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let mut cfg = Config::default().checker;
    cfg.data_dir = root.join("data");
    cfg.blocklist_db = dir.join("blocked.redb");
    Arc::new(Checker::new(&cfg).unwrap())
}

#[tokio::test]
async fn published_gvlks_resolve_to_their_edition() {
    let checker = checker();
    let keys = GVLKS.iter().map(|(k, _)| k.to_string()).collect();
    let reports = checker.check_many(keys, CheckOptions { online: false }).await;
    for ((key, edition), r) in GVLKS.iter().zip(&reports) {
        assert_eq!(r.status, KeyStatus::Valid, "{key}: {}", r.message);
        let d = r.details.as_ref().unwrap();
        assert_eq!(d.edition_id, *edition, "{key}");
        assert_eq!(d.key_type, "Volume:GVLK", "{key}");
        assert!(!d.product.is_empty(), "{key}");
    }
}

#[test]
fn defaults_round_trip_through_toml() {
    let cfg = Config::default();
    let text = toml::to_string_pretty(&cfg).unwrap();
    let back: Config = toml::from_str(&text).unwrap();
    assert_eq!(back.checker, cfg.checker);
}
