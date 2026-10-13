export type VerdictType = "BENIGN" | "ADWARE" | "MALWARE";
export type RiskLevelType = "SAFE" | "HIGH" | "CRITICAL";

export interface RiskPermission {
  name: string;
  risk: "HIGH" | "MEDIUM" | "LOW";
  weight: number;
  percentage: number;
  description?: string;
}

export interface FeatureSummary {
  total_permissions: number;
  high_risk_count: number;
  medium_risk_count: number;
  low_risk_count: number;
  api_calls_detected: number;
  ad_sdks_detected: number;
}

export interface ScanResult {
  success: boolean;
  filename: string;
  package_name: string;
  app_size_kb: number;
  verdict: VerdictType;
  confidence: number;
  risk_level: RiskLevelType;
  probabilities: {
    Benign: number;
    Adware: number;
    Malware: number;
  };
  feature_summary: FeatureSummary;
  risk_permissions: RiskPermission[];
  suspicious_apis: string[];
  ad_sdks: string[];
  datasets_used: string[];
  model_info: {
    name: string;
    accuracy: number;
    trained_samples: number;
    datasets: number;
  };
  timestamp?: string;
  sha256_mock?: string;
}

export interface BenchmarkSample {
  id: "adware" | "benign" | "malware";
  title: string;
  packageName: string;
  fileName: string;
  version: string;
  sizeKb: number;
  datasetSource: string;
  tag: "Adware" | "Benign" | "Malware";
  shortDesc: string;
  behaviorNote: string;
}

export interface CitationItem {
  id: number;
  authors: string;
  year: string;
  title: string;
  journal: string;
  volumeInfo: string;
  architectureRole: string;
  doiOrUrl?: string;
}
