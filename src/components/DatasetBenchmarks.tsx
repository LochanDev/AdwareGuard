import React from "react";
import { Database, Filter, Layers, CheckCircle2, FileText, ArrowUpRight } from "lucide-react";

export const DatasetBenchmarks: React.FC = () => {
  const datasets = [
    {
      name: "CICMalDroid 2020",
      institution: "Canadian Institute for Cybersecurity (UNB)",
      rawSamples: "17,341",
      curatedSamples: "11,598",
      features: "301 static + 263 dynamic (564 hybrid)",
      classes: "Adware, Banking, SMS, Riskware, Benign",
      focus: "Primary benchmark for aggressive adware family patterns and evasion heuristics.",
    },
    {
      name: "CICAndMal2017",
      institution: "Canadian Institute for Cybersecurity (UNB)",
      rawSamples: "10,854",
      curatedSamples: "10,428",
      features: "80 network flow & static characteristics",
      classes: "Adware, Ransomware, Scareware, Benign",
      focus: "Ground truth for network-based telemetry and ad server beaconing signatures.",
    },
    {
      name: "Drebin Dataset",
      institution: "Technische Universität Braunschweig",
      rawSamples: "128,013",
      curatedSamples: "47,893",
      features: "Top 200 permissions + 150 DEX API calls",
      classes: "Malware, Benign (VirusTotal verified)",
      focus: "Foundational repository for broad permission combinations and API invocation graphs.",
    },
    {
      name: "AndroZoo",
      institution: "University of Luxembourg",
      rawSamples: "50,000",
      curatedSamples: "50,000",
      features: "Manifest permissions + DEX bytecode opcodes",
      classes: "Benign (VT=0) & Malware (VT>=4)",
      focus: "Massive scale calibration to ensure low false positive rates on benign store apps.",
    },
    {
      name: "MalGenome Project",
      institution: "North Carolina State University",
      rawSamples: "3,799",
      curatedSamples: "3,621",
      features: "215 high-confidence permission features",
      classes: "49 Android Malware Families",
      focus: "Historical reference samples providing verified lineage for Android Trojan families.",
    },
  ];

  return (
    <div className="space-y-8">
      {/* Overview header */}
      <div className="rounded-xl border border-slate-200 bg-white p-6 dark:border-slate-800 dark:bg-slate-900 transition-colors">
        <div className="max-w-3xl">
          <div className="flex items-center gap-2 text-xs font-semibold uppercase tracking-wider text-slate-500 dark:text-slate-400">
            <Database className="h-4 w-4 text-sky-600 dark:text-sky-400" />
            Empirical Foundation
          </div>
          <h2 className="mt-1 text-2xl font-bold tracking-tight text-slate-900 dark:text-slate-100">
            Benchmark Datasets &amp; Feature Preprocessing
          </h2>
          <p className="mt-2 text-sm leading-relaxed text-slate-600 dark:text-slate-400">
            To prevent overfitting to any single repository or vendor, AdwareGuard aggregates and normalizes
            evidence from 5 distinct academic malware corpuses totaling <strong>161,007 raw APK records</strong>.
            Following stringent deduplication and variance analysis, a balanced subset of <strong>73,109 samples</strong>
            was synthesized into the final 360-dimensional multimodal space.
          </p>
        </div>

        {/* Quick metrics row */}
        <div className="mt-6 grid grid-cols-2 gap-4 sm:grid-cols-4 pt-6 border-t border-slate-100 dark:border-slate-800/80">
          <div className="rounded-lg bg-slate-50 p-3.5 dark:bg-slate-800/50">
            <span className="text-xs text-slate-500 dark:text-slate-400">Raw Input Corpuses</span>
            <div className="mt-1 font-mono text-xl font-bold text-slate-900 dark:text-slate-100">161,007</div>
            <span className="text-[11px] text-slate-500">Unfiltered records</span>
          </div>

          <div className="rounded-lg bg-slate-50 p-3.5 dark:bg-slate-800/50">
            <span className="text-xs text-slate-500 dark:text-slate-400">Cleaned &amp; Deduplicated</span>
            <div className="mt-1 font-mono text-xl font-bold text-slate-900 dark:text-slate-100">73,109</div>
            <span className="text-[11px] text-slate-500">Unique APK hashes</span>
          </div>

          <div className="rounded-lg bg-slate-50 p-3.5 dark:bg-slate-800/50">
            <span className="text-xs text-slate-500 dark:text-slate-400">Balanced Vector Space</span>
            <div className="mt-1 font-mono text-xl font-bold text-slate-900 dark:text-slate-100">219,327</div>
            <span className="text-[11px] text-slate-500">Post-SMOTE augmentation</span>
          </div>

          <div className="rounded-lg bg-slate-50 p-3.5 dark:bg-slate-800/50">
            <span className="text-xs text-slate-500 dark:text-slate-400">Multimodal Dimension</span>
            <div className="mt-1 font-mono text-xl font-bold text-slate-900 dark:text-slate-100">360-D</div>
            <span className="text-[11px] text-slate-500">Permissions + APIs + Meta</span>
          </div>
        </div>
      </div>

      {/* Dataset comparison table */}
      <div className="overflow-hidden rounded-xl border border-slate-200 bg-white dark:border-slate-800 dark:bg-slate-900 transition-colors">
        <div className="border-b border-slate-200 px-6 py-4 dark:border-slate-800">
          <h3 className="font-semibold text-slate-900 dark:text-slate-100">
            Benchmark Lineage &amp; Corpus Distribution
          </h3>
          <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
            Detailed breakdown of sample volumes, extraction feature sets, and target classes per benchmark.
          </p>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-sm">
            <thead className="border-b border-slate-200 bg-slate-50 text-xs font-semibold uppercase tracking-wider text-slate-600 dark:border-slate-800 dark:bg-slate-800/60 dark:text-slate-300">
              <tr>
                <th className="px-6 py-3.5">Dataset Corpus</th>
                <th className="px-4 py-3.5">Corpus Origin</th>
                <th className="px-4 py-3.5 font-mono text-right">Raw</th>
                <th className="px-4 py-3.5 font-mono text-right">Curated</th>
                <th className="px-4 py-3.5">Feature Extraction Scheme</th>
                <th className="px-6 py-3.5">Target Classification Scope</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100 dark:divide-slate-800/60">
              {datasets.map((ds, idx) => (
                <tr key={idx} className="hover:bg-slate-50/70 dark:hover:bg-slate-800/40 transition-colors">
                  <td className="px-6 py-4 font-semibold text-slate-900 dark:text-slate-100">
                    <div>{ds.name}</div>
                    <div className="text-xs font-normal text-slate-500 dark:text-slate-400 mt-0.5 max-w-xs line-clamp-1">
                      {ds.focus}
                    </div>
                  </td>
                  <td className="px-4 py-4 text-slate-600 dark:text-slate-400 text-xs">
                    {ds.institution}
                  </td>
                  <td className="px-4 py-4 text-right font-mono text-xs text-slate-500 dark:text-slate-400">
                    {ds.rawSamples}
                  </td>
                  <td className="px-4 py-4 text-right font-mono text-xs font-medium text-slate-900 dark:text-slate-200">
                    {ds.curatedSamples}
                  </td>
                  <td className="px-4 py-4 text-xs text-slate-600 dark:text-slate-300">
                    {ds.features}
                  </td>
                  <td className="px-6 py-4 text-xs text-slate-600 dark:text-slate-400">
                    <span className="rounded bg-slate-100 px-2 py-1 text-[11px] font-medium text-slate-700 dark:bg-slate-800 dark:text-slate-300">
                      {ds.classes}
                    </span>
                  </td>
                </tr>
              ))}
              <tr className="bg-slate-50/80 font-medium dark:bg-slate-800/60">
                <td className="px-6 py-4 text-slate-900 dark:text-slate-100 font-bold">
                  Unified Benchmark Suite
                </td>
                <td className="px-4 py-4 text-xs text-slate-600 dark:text-slate-400">
                  Cross-Institutional Joint
                </td>
                <td className="px-4 py-4 text-right font-mono text-xs font-bold text-slate-900 dark:text-slate-100">
                  161,007
                </td>
                <td className="px-4 py-4 text-right font-mono text-xs font-bold text-sky-600 dark:text-sky-400">
                  73,109
                </td>
                <td className="px-4 py-4 text-xs font-semibold text-slate-900 dark:text-slate-100">
                  360-D Multimodal Dense Vector
                </td>
                <td className="px-6 py-4 text-xs font-bold text-slate-900 dark:text-slate-100">
                  Benign (33.3%) &bull; Adware (33.3%) &bull; Malware (33.3%)
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>

      {/* Preprocessing pipeline stages */}
      <div className="rounded-xl border border-slate-200 bg-white p-6 dark:border-slate-800 dark:bg-slate-900 transition-colors">
        <h3 className="font-semibold text-slate-900 dark:text-slate-100">
          Data Engineering &amp; Normalization Pipeline
        </h3>
        <p className="mt-1 text-xs text-slate-500 dark:text-slate-400">
          How raw heterogeneous APK artifacts are transformed into reproducible input tensors.
        </p>

        <div className="mt-6 grid gap-4 sm:grid-cols-3">
          <div className="rounded-lg border border-slate-200/80 p-4 dark:border-slate-800">
            <div className="flex items-center gap-2 font-medium text-slate-900 dark:text-slate-200 text-sm">
              <span className="flex h-6 w-6 items-center justify-center rounded-full bg-slate-100 text-xs font-bold text-slate-700 dark:bg-slate-800 dark:text-slate-300">
                1
              </span>
              Variance &amp; Deduplication
            </div>
            <p className="mt-2 text-xs leading-relaxed text-slate-600 dark:text-slate-400">
              SHA-256 fingerprinting removes duplicate package repackagings. Features with variance &lt; 0.01 (e.g. ubiquitous standard permissions like VIBRATE) are pruned to eliminate noise.
            </p>
          </div>

          <div className="rounded-lg border border-slate-200/80 p-4 dark:border-slate-800">
            <div className="flex items-center gap-2 font-medium text-slate-900 dark:text-slate-200 text-sm">
              <span className="flex h-6 w-6 items-center justify-center rounded-full bg-slate-100 text-xs font-bold text-slate-700 dark:bg-slate-800 dark:text-slate-300">
                2
              </span>
              SMOTE Balancing
            </div>
            <p className="mt-2 text-xs leading-relaxed text-slate-600 dark:text-slate-400">
              Natural malware datasets suffer from heavy class imbalance. Synthetic Minority Over-sampling (SMOTE) synthesizes balanced vector neighborhoods, ensuring equal gradient contribution.
            </p>
          </div>

          <div className="rounded-lg border border-slate-200/80 p-4 dark:border-slate-800">
            <div className="flex items-center gap-2 font-medium text-slate-900 dark:text-slate-200 text-sm">
              <span className="flex h-6 w-6 items-center justify-center rounded-full bg-slate-100 text-xs font-bold text-slate-700 dark:bg-slate-800 dark:text-slate-300">
                3
              </span>
              Stratified 70/15/15 Split
            </div>
            <p className="mt-2 text-xs leading-relaxed text-slate-600 dark:text-slate-400">
              Zero package leakage between training (70%), validation (15%), and holdout test (15%) partitions. Families are grouped to prevent memorization of repackaged sibling APKs.
            </p>
          </div>
        </div>
      </div>
    </div>
  );
};
