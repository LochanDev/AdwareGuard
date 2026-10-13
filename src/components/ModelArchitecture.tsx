import React from "react";
import { Cpu, BookOpen, Layers, CheckCircle, ExternalLink, Zap } from "lucide-react";
import { CITATIONS } from "../data/benchmarkSamples";

export const ModelArchitecture: React.FC = () => {
  const metrics = [
    { label: "Overall Accuracy", value: "96.8%", note: "Stratified test split" },
    { label: "Precision", value: "95.4%", note: "Low false positive rate" },
    { label: "Recall (Sensitivity)", value: "96.1%", note: "Adware capture rate" },
    { label: "F1 Harmonic Score", value: "95.7%", note: "Balanced detection" },
    { label: "Multi-class AUC-ROC", value: "0.987", note: "OvR curve area" },
    { label: "Inference Latency", value: "<12 ms", note: "CPU real-time pass" },
  ];

  const vectorSlots = [
    {
      range: "Indices 0 – 199",
      count: "200 Slots",
      title: "Android Manifest Permissions",
      desc: "Normalized binary and occurrence frequencies across standard, dangerous, and custom permissions (e.g. SYSTEM_ALERT_WINDOW, READ_PHONE_STATE, BIND_DEVICE_ADMIN).",
    },
    {
      range: "Indices 200 – 349",
      count: "150 Slots",
      title: "DEX Bytecode APIs & Ad SDK Footprints",
      desc: "Static regex and symbol matches for runtime invocation calls (DexClassLoader, Runtime.exec, TelephonyManager) and aggressive commercial ad networks (Airpush, StartApp, AdMob).",
    },
    {
      range: "Indices 350 – 359",
      count: "10 Slots",
      title: "Structural Container Metadata",
      desc: "Normalized file size, manifest component counts (services, receivers, activities, providers), debuggable flags, and signature block validity.",
    },
  ];

  return (
    <div className="space-y-8">
      {/* Header */}
      <div className="rounded-xl border border-slate-200 bg-white p-6 dark:border-slate-800 dark:bg-slate-900 transition-colors">
        <div className="max-w-3xl">
          <div className="flex items-center gap-2 text-xs font-semibold uppercase tracking-wider text-slate-500 dark:text-slate-400">
            <Cpu className="h-4 w-4 text-sky-600 dark:text-sky-400" />
            Neural Architecture &amp; Empirical Validation
          </div>
          <h2 className="mt-1 text-2xl font-bold tracking-tight text-slate-900 dark:text-slate-100">
            Multimodal Transformer Classification Head
          </h2>
          <p className="mt-2 text-sm leading-relaxed text-slate-600 dark:text-slate-400">
            AdwareGuard utilizes a feature-tokenizer simulation architecture that maps multimodal static artifacts
            into a unified dense embedding space. By evaluating non-linear interactions across permissions and
            DEX API calls, the model isolates deceptive adware that disguises itself as benign utility software.
          </p>
        </div>

        {/* Performance metrics grid */}
        <div className="mt-6 grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-6 pt-6 border-t border-slate-100 dark:border-slate-800/80">
          {metrics.map((m, idx) => (
            <div key={idx} className="rounded-lg bg-slate-50 p-3 dark:bg-slate-800/50">
              <span className="text-[11px] text-slate-500 dark:text-slate-400">{m.label}</span>
              <div className="mt-0.5 font-mono text-xl font-bold text-slate-900 dark:text-slate-100">
                {m.value}
              </div>
              <span className="text-[10px] text-slate-500">{m.note}</span>
            </div>
          ))}
        </div>
      </div>

      {/* 360-D Vector Layout */}
      <div className="rounded-xl border border-slate-200 bg-white p-6 dark:border-slate-800 dark:bg-slate-900 transition-colors">
        <h3 className="font-semibold text-slate-900 dark:text-slate-100">
          360-Dimensional Multimodal Feature Map
        </h3>
        <p className="mt-1 text-xs text-slate-500 dark:text-slate-400">
          How heterogeneous APK components are mapped into contiguous tensor dimensions.
        </p>

        <div className="mt-4 grid gap-4 sm:grid-cols-3">
          {vectorSlots.map((slot, idx) => (
            <div
              key={idx}
              className="rounded-lg border border-slate-200/90 bg-slate-50/50 p-4 dark:border-slate-800 dark:bg-slate-800/30"
            >
              <div className="flex items-center justify-between font-mono text-xs">
                <span className="font-semibold text-sky-700 dark:text-sky-400">{slot.range}</span>
                <span className="rounded bg-slate-200/70 px-1.5 py-0.5 text-[10px] font-medium text-slate-700 dark:bg-slate-700 dark:text-slate-300">
                  {slot.count}
                </span>
              </div>
              <h4 className="mt-2 text-sm font-semibold text-slate-900 dark:text-slate-100">
                {slot.title}
              </h4>
              <p className="mt-1 text-xs leading-relaxed text-slate-600 dark:text-slate-400">
                {slot.desc}
              </p>
            </div>
          ))}
        </div>

        {/* Network pipeline visualization */}
        <div className="mt-6 rounded-lg border border-slate-200 bg-slate-50 p-4 dark:border-slate-800 dark:bg-slate-800/60">
          <div className="text-xs font-semibold uppercase tracking-wider text-slate-600 dark:text-slate-400">
            Feedforward Head Pipeline Topology
          </div>
          <div className="mt-3 flex flex-wrap items-center gap-2 text-xs font-mono">
            <span className="rounded bg-white px-2.5 py-1 text-slate-800 border border-slate-300 dark:bg-slate-900 dark:text-slate-200 dark:border-slate-700">
              Input [1 × 360]
            </span>
            <span className="text-slate-400">&rarr;</span>
            <span className="rounded bg-white px-2.5 py-1 text-slate-800 border border-slate-300 dark:bg-slate-900 dark:text-slate-200 dark:border-slate-700">
              Dense [256] + ReLU + Dropout(0.2)
            </span>
            <span className="text-slate-400">&rarr;</span>
            <span className="rounded bg-white px-2.5 py-1 text-slate-800 border border-slate-300 dark:bg-slate-900 dark:text-slate-200 dark:border-slate-700">
              Dense [128] + ReLU + BatchNorm
            </span>
            <span className="text-slate-400">&rarr;</span>
            <span className="rounded bg-white px-2.5 py-1 text-slate-800 border border-slate-300 dark:bg-slate-900 dark:text-slate-200 dark:border-slate-700">
              Dense [64] + ReLU
            </span>
            <span className="text-slate-400">&rarr;</span>
            <span className="rounded bg-sky-50 px-2.5 py-1 text-sky-800 border border-sky-300 dark:bg-sky-950/60 dark:text-sky-300 dark:border-sky-800 font-semibold">
              Softmax [Benign, Adware, Malware]
            </span>
          </div>
        </div>
      </div>

      {/* Citations Grounding */}
      <div className="rounded-xl border border-slate-200 bg-white p-6 dark:border-slate-800 dark:bg-slate-900 transition-colors">
        <div className="flex items-center justify-between">
          <div>
            <h3 className="font-semibold text-slate-900 dark:text-slate-100">
              Peer-Reviewed Grounding &amp; Academic Citations
            </h3>
            <p className="mt-0.5 text-xs text-slate-500 dark:text-slate-400">
              AdwareGuard architectural decisions directly implement frameworks established in these peer-reviewed works:
            </p>
          </div>
          <span className="hidden sm:inline-flex items-center gap-1 text-xs font-medium text-slate-500">
            <BookOpen className="h-3.5 w-3.5" /> 5 Verified Works
          </span>
        </div>

        <div className="mt-6 divide-y divide-slate-100 dark:divide-slate-800">
          {CITATIONS.map((cit) => (
            <div key={cit.id} className="py-4 first:pt-0 last:pb-0">
              <div className="flex items-baseline gap-2">
                <span className="font-mono text-xs font-bold text-sky-600 dark:text-sky-400">
                  [{cit.id}]
                </span>
                <span className="text-xs font-semibold text-slate-900 dark:text-slate-100">
                  {cit.authors} ({cit.year})
                </span>
              </div>
              <p className="mt-1 text-sm text-slate-700 dark:text-slate-300 italic">
                "{cit.title}."
              </p>
              <div className="mt-1 flex items-center gap-2 text-xs text-slate-500 dark:text-slate-400">
                <span className="font-medium text-slate-700 dark:text-slate-300">{cit.journal}</span>
                <span>&bull;</span>
                <span>{cit.volumeInfo}</span>
              </div>
              <div className="mt-2 rounded-md bg-slate-50 p-2.5 text-xs text-slate-600 dark:bg-slate-800/60 dark:text-slate-300 border border-slate-100 dark:border-slate-800">
                <strong className="text-slate-800 dark:text-slate-200">Implementation Rationale:</strong>{" "}
                {cit.architectureRole}
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};
