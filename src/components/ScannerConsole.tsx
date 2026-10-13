import React, { useState, useRef } from "react";
import {
  Upload,
  FileCheck,
  X,
  AlertTriangle,
  ShieldCheck,
  ShieldAlert,
  ShieldX,
  Copy,
  Check,
  Download,
  RotateCcw,
  Sparkles,
  Terminal,
  Activity,
  Layers,
  ChevronRight,
  ExternalLink,
  Code,
  Info,
  Radio,
  FileCode,
} from "lucide-react";
import { ScanResult, BenchmarkSample } from "../types";
import { BENCHMARK_SAMPLES, PERMISSION_EXPLANATIONS } from "../data/benchmarkSamples";

interface ScannerConsoleProps {
  onScanFile: (file: File) => Promise<void>;
  onScanSample: (sampleType: "adware" | "benign" | "malware") => Promise<void>;
  isScanning: boolean;
  scanStep: number;
  scanResult: ScanResult | null;
  errorMessage: string | null;
  onClearError: () => void;
  onReset: () => void;
}

export const ScannerConsole: React.FC<ScannerConsoleProps> = ({
  onScanFile,
  onScanSample,
  isScanning,
  scanStep,
  scanResult,
  errorMessage,
  onClearError,
  onReset,
}) => {
  const [activeIngestionMode, setActiveIngestionMode] = useState<"upload" | "benchmark">("upload");
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [isDragging, setIsDragging] = useState<boolean>(false);
  const [activeReportTab, setActiveReportTab] = useState<"permissions" | "apis" | "summary">("permissions");
  const [permissionFilter, setPermissionFilter] = useState<"ALL" | "HIGH" | "MEDIUM">("ALL");
  const [copiedPackage, setCopiedPackage] = useState<boolean>(false);
  const [copiedSummary, setCopiedSummary] = useState<boolean>(false);

  const fileInputRef = useRef<HTMLInputElement | null>(null);

  const handleFileSelect = (file: File) => {
    onClearError();
    const name = file.name.toLowerCase();
    const isApkLike =
      name.endsWith(".apk") ||
      name.endsWith(".xapk") ||
      name.endsWith(".zip") ||
      name.endsWith(".aab") ||
      !name.includes(".");

    if (!isApkLike) {
      alert("Please upload an Android package (.apk, .xapk, or .zip archive).");
      return;
    }

    setSelectedFile(file);
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(false);
    if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
      handleFileSelect(e.dataTransfer.files[0]);
    }
  };

  const startFileUploadScan = () => {
    if (selectedFile) {
      onScanFile(selectedFile);
    }
  };

  const copyToClipboard = (text: string, type: "pkg" | "summary") => {
    navigator.clipboard.writeText(text);
    if (type === "pkg") {
      setCopiedPackage(true);
      setTimeout(() => setCopiedPackage(false), 2000);
    } else {
      setCopiedSummary(true);
      setTimeout(() => setCopiedSummary(false), 2000);
    }
  };

  const downloadJsonReport = () => {
    if (!scanResult) return;
    const blob = new Blob([JSON.stringify(scanResult, null, 2)], {
      type: "application/json",
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `adwareguard_report_${scanResult.package_name || "scan"}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const filteredPermissions = (scanResult?.risk_permissions || []).filter((p) => {
    if (permissionFilter === "ALL") return true;
    return p.risk === permissionFilter;
  });

  return (
    <div className="space-y-6">
      {/* 1. INGESTION WORKBENCH (Hidden when scanning or when results are shown) */}
      {!isScanning && !scanResult && (
        <div className="rounded-xl border border-slate-200 bg-white shadow-xs dark:border-slate-800 dark:bg-slate-900 transition-colors">
          {/* Header & Ingestion Selector */}
          <div className="border-b border-slate-200 p-6 dark:border-slate-800">
            <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
              <div>
                <h2 className="text-xl font-bold tracking-tight text-slate-900 dark:text-slate-100">
                  Target Ingestion &amp; Static Decompilation
                </h2>
                <p className="mt-1 text-xs text-slate-500 dark:text-slate-400">
                  Upload an Android package file or load pre-compiled test vectors from our benchmark library.
                </p>
              </div>

              {/* Toggle switch between Upload and Benchmark Library */}
              <div className="inline-flex rounded-lg bg-slate-100 p-1 dark:bg-slate-800/80 border border-slate-200/80 dark:border-slate-700/60 self-start sm:self-auto">
                <button
                  type="button"
                  onClick={() => setActiveIngestionMode("upload")}
                  className={`flex items-center gap-1.5 rounded-md px-3 py-1.5 text-xs font-medium transition-colors ${
                    activeIngestionMode === "upload"
                      ? "bg-white text-slate-900 shadow-xs dark:bg-slate-700 dark:text-white"
                      : "text-slate-600 hover:text-slate-900 dark:text-slate-400 dark:hover:text-white"
                  }`}
                >
                  <Upload className="h-3.5 w-3.5" />
                  <span>Upload Local APK</span>
                </button>
                <button
                  type="button"
                  onClick={() => setActiveIngestionMode("benchmark")}
                  className={`flex items-center gap-1.5 rounded-md px-3 py-1.5 text-xs font-medium transition-colors ${
                    activeIngestionMode === "benchmark"
                      ? "bg-white text-slate-900 shadow-xs dark:bg-slate-700 dark:text-white"
                      : "text-slate-600 hover:text-slate-900 dark:text-slate-400 dark:hover:text-white"
                  }`}
                >
                  <Layers className="h-3.5 w-3.5" />
                  <span>Benchmark Vectors (3)</span>
                </button>
              </div>
            </div>
          </div>

          <div className="p-6">
            {/* ERROR BANNER */}
            {errorMessage && (
              <div className="mb-6 flex items-start justify-between rounded-lg border border-red-200 bg-red-50 p-4 text-xs text-red-800 dark:border-red-900/60 dark:bg-red-950/40 dark:text-red-300">
                <div className="flex items-center gap-2">
                  <AlertTriangle className="h-4 w-4 shrink-0 text-red-600 dark:text-red-400" />
                  <span>{errorMessage}</span>
                </div>
                <button
                  type="button"
                  onClick={onClearError}
                  className="rounded p-1 hover:bg-red-100 dark:hover:bg-red-900/50"
                >
                  <X className="h-3.5 w-3.5" />
                </button>
              </div>
            )}

            {/* TAB A: UPLOAD LOCAL APK */}
            {activeIngestionMode === "upload" && (
              <div className="space-y-4">
                <div
                  onDragOver={(e) => {
                    e.preventDefault();
                    setIsDragging(true);
                  }}
                  onDragLeave={() => setIsDragging(false)}
                  onDrop={handleDrop}
                  onClick={() => fileInputRef.current?.click()}
                  className={`group relative flex cursor-pointer flex-col items-center justify-center rounded-xl border-2 border-dashed p-8 sm:p-12 text-center transition-all ${
                    isDragging
                      ? "border-sky-500 bg-sky-50/50 dark:border-sky-400 dark:bg-sky-950/20"
                      : "border-slate-300 hover:border-slate-400 dark:border-slate-700 dark:hover:border-slate-600 bg-slate-50/50 dark:bg-slate-800/30"
                  }`}
                >
                  <input
                    ref={fileInputRef}
                    type="file"
                    accept=".apk,.xapk,.zip,.aab"
                    className="hidden"
                    onChange={(e) => {
                      if (e.target.files && e.target.files.length > 0) {
                        handleFileSelect(e.target.files[0]);
                      }
                    }}
                  />

                  <div className="flex h-12 w-12 items-center justify-center rounded-full bg-slate-200/80 text-slate-700 dark:bg-slate-800 dark:text-slate-300 group-hover:scale-105 transition-transform">
                    <Upload className="h-6 w-6" />
                  </div>

                  <p className="mt-3 text-sm font-semibold text-slate-900 dark:text-slate-100">
                    Select an Android package or drag &amp; drop file here
                  </p>
                  <p className="mt-1 text-xs text-slate-500 dark:text-slate-400 max-w-sm">
                    Accepts compiled <code className="font-mono text-slate-700 dark:text-slate-300">.apk</code>,{" "}
                    <code className="font-mono text-slate-700 dark:text-slate-300">.xapk</code>, or{" "}
                    <code className="font-mono text-slate-700 dark:text-slate-300">.zip</code> archives up to 250MB.
                  </p>
                  <div className="mt-4 inline-flex items-center gap-1.5 rounded-md bg-white px-3 py-1.5 text-xs font-medium text-slate-700 shadow-xs border border-slate-200 dark:bg-slate-800 dark:text-slate-200 dark:border-slate-700">
                    Browse Local Storage
                  </div>
                </div>

                {/* Selected File Banner */}
                {selectedFile && (
                  <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between rounded-lg border border-slate-200 bg-slate-50/80 p-4 dark:border-slate-800 dark:bg-slate-800/60 gap-3">
                    <div className="flex items-center gap-3 min-w-0">
                      <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-lg bg-sky-100 text-sky-700 dark:bg-sky-950/70 dark:text-sky-300">
                        <FileCode className="h-5 w-5" />
                      </div>
                      <div className="min-w-0">
                        <div className="font-mono text-xs sm:text-sm font-semibold text-slate-900 dark:text-slate-100 truncate">
                          {selectedFile.name}
                        </div>
                        <div className="text-[11px] text-slate-500 dark:text-slate-400">
                          {(selectedFile.size / 1024).toLocaleString(undefined, {
                            maximumFractionDigits: 1,
                          })}{" "}
                          KB &bull; Ready for Bytecode Decompilation
                        </div>
                      </div>
                    </div>

                    <div className="flex items-center gap-2 self-end sm:self-auto">
                      <button
                        type="button"
                        onClick={(e) => {
                          e.stopPropagation();
                          setSelectedFile(null);
                          if (fileInputRef.current) fileInputRef.current.value = "";
                        }}
                        className="rounded-md border border-slate-200 px-2.5 py-1.5 text-xs font-medium text-slate-600 hover:bg-slate-100 dark:border-slate-700 dark:text-slate-300 dark:hover:bg-slate-800"
                      >
                        Remove
                      </button>
                      <button
                        type="button"
                        onClick={startFileUploadScan}
                        className="rounded-md bg-slate-900 px-4 py-1.5 text-xs font-semibold text-white hover:bg-slate-800 dark:bg-sky-600 dark:hover:bg-sky-500 shadow-xs"
                      >
                        Execute Analysis
                      </button>
                    </div>
                  </div>
                )}
              </div>
            )}

            {/* TAB B: BENCHMARK SAMPLE LIBRARY */}
            {activeIngestionMode === "benchmark" && (
              <div className="space-y-3">
                <div className="text-xs text-slate-500 dark:text-slate-400 mb-2">
                  Select a reference sample from verified academic repositories to observe classification attention weights:
                </div>

                <div className="grid gap-3 sm:grid-cols-3">
                  {BENCHMARK_SAMPLES.map((sample) => (
                    <div
                      key={sample.id}
                      className="group flex flex-col justify-between rounded-xl border border-slate-200 bg-slate-50/50 p-4 hover:border-slate-300 dark:border-slate-800 dark:bg-slate-800/40 dark:hover:border-slate-700 transition-all"
                    >
                      <div>
                        <div className="flex items-center justify-between">
                          <span
                            className={`inline-flex items-center rounded-md px-2 py-0.5 text-[10px] font-bold uppercase tracking-wider ${
                              sample.tag === "Adware"
                                ? "bg-amber-100 text-amber-800 dark:bg-amber-950/60 dark:text-amber-300"
                                : sample.tag === "Benign"
                                ? "bg-emerald-100 text-emerald-800 dark:bg-emerald-950/60 dark:text-emerald-300"
                                : "bg-red-100 text-red-800 dark:bg-red-950/60 dark:text-red-300"
                            }`}
                          >
                            {sample.tag}
                          </span>
                          <span className="font-mono text-[11px] text-slate-500">
                            {sample.sizeKb.toLocaleString()} KB
                          </span>
                        </div>

                        <h4 className="mt-2 text-sm font-semibold text-slate-900 dark:text-slate-100">
                          {sample.title}
                        </h4>
                        <div className="font-mono text-[11px] text-slate-500 dark:text-slate-400 truncate mt-0.5">
                          {sample.packageName}
                        </div>
                        <p className="mt-2 text-xs text-slate-600 dark:text-slate-400 leading-relaxed">
                          {sample.shortDesc}
                        </p>
                      </div>

                      <div className="mt-4 pt-3 border-t border-slate-200/60 dark:border-slate-800/80 flex items-center justify-between">
                        <span className="text-[10px] text-slate-500">{sample.datasetSource}</span>
                        <button
                          type="button"
                          onClick={() => onScanSample(sample.id)}
                          className="flex items-center gap-1 rounded bg-white px-2.5 py-1 text-xs font-medium text-slate-800 shadow-2xs border border-slate-200 hover:bg-slate-50 dark:bg-slate-800 dark:text-slate-200 dark:border-slate-700 dark:hover:bg-slate-700"
                        >
                          <span>Analyze</span>
                          <ChevronRight className="h-3 w-3" />
                        </button>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        </div>
      )}

      {/* 2. SCANNING & TELEMETRY PROGRESS STREAM */}
      {isScanning && (
        <div className="rounded-xl border border-slate-200 bg-white p-6 dark:border-slate-800 dark:bg-slate-900 transition-colors">
          <div className="flex items-center gap-3">
            <div className="relative flex h-8 w-8 items-center justify-center">
              <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-sky-400 opacity-50"></span>
              <span className="relative inline-flex h-4 w-4 rounded-full bg-sky-600 dark:bg-sky-400"></span>
            </div>
            <div>
              <h3 className="font-semibold text-slate-900 dark:text-slate-100">
                Decompiling &amp; Synthesizing Multimodal Vector...
              </h3>
              <p className="text-xs text-slate-500 dark:text-slate-400">
                Executing static DEX disassembly, manifest parsing, and feedforward transformer evaluation
              </p>
            </div>
          </div>

          {/* Progress bar */}
          <div className="mt-6">
            <div className="flex justify-between text-xs font-mono text-slate-500 mb-1">
              <span>Stage {scanStep} of 4</span>
              <span>{Math.min(100, scanStep * 25)}%</span>
            </div>
            <div className="h-2 w-full overflow-hidden rounded-full bg-slate-100 dark:bg-slate-800">
              <div
                className="h-full bg-sky-600 dark:bg-sky-500 transition-all duration-500 ease-out"
                style={{ width: `${Math.min(100, scanStep * 25)}%` }}
              />
            </div>
          </div>

          {/* Live telemetry console */}
          <div className="mt-6 rounded-lg bg-slate-950 p-4 font-mono text-xs text-slate-300 border border-slate-800">
            <div className="flex items-center gap-2 text-slate-500 text-[11px] pb-2 border-b border-slate-800 mb-2">
              <Terminal className="h-3.5 w-3.5" />
              <span>DIAGNOSTIC PIPELINE MONITOR</span>
            </div>
            <div className="space-y-1.5 text-[11px]">
              <div className={scanStep >= 1 ? "text-emerald-400" : "text-slate-600"}>
                {scanStep >= 1 ? "✓ [00:00.12] Central Directory verified. AndroidManifest.xml parsed successfully." : "○ [00:00.12] Waiting for manifest stream..."}
              </div>
              <div className={scanStep >= 2 ? "text-emerald-400" : "text-slate-600"}>
                {scanStep >= 2 ? "✓ [00:00.48] Disassembled classes.dex symbol tables & scanned 360 multimodal slots." : "○ [00:00.48] Disassembling Dalvik bytecode..."}
              </div>
              <div className={scanStep >= 3 ? "text-emerald-400" : "text-slate-600"}>
                {scanStep >= 3 ? "✓ [00:00.86] Vector tokenization complete. Evaluating feedforward classification head." : "○ [00:00.86] Running model forward pass..."}
              </div>
              <div className={scanStep >= 4 ? "text-emerald-400" : "text-slate-600"}>
                {scanStep >= 4 ? "✓ [00:01.19] Attention weights computed. Generating final security attribution report." : "○ [00:01.19] Synthesizing attention weights..."}
              </div>
            </div>
          </div>
        </div>
      )}

      {/* 3. FORENSIC INSPECTION REPORT (Shown after scan completes) */}
      {scanResult && !isScanning && (
        <div className="space-y-6">
          {/* Executive Diagnostic Card */}
          <div className="rounded-xl border border-slate-200 bg-white p-6 shadow-xs dark:border-slate-800 dark:bg-slate-900 transition-colors">
            {/* Top Bar: Metadata & Actions */}
            <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3 border-b border-slate-100 pb-4 dark:border-slate-800/80">
              <div className="flex items-center gap-2">
                <span className="rounded bg-slate-100 px-2 py-0.5 font-mono text-xs font-semibold text-slate-800 dark:bg-slate-800 dark:text-slate-200">
                  {scanResult.filename}
                </span>
                <button
                  type="button"
                  onClick={() => copyToClipboard(scanResult.package_name, "pkg")}
                  className="flex items-center gap-1 font-mono text-xs text-slate-500 hover:text-slate-800 dark:hover:text-slate-200 transition-colors"
                  title="Copy package identifier"
                >
                  <span className="max-w-[180px] sm:max-w-xs truncate">{scanResult.package_name}</span>
                  {copiedPackage ? (
                    <Check className="h-3.5 w-3.5 text-emerald-600" />
                  ) : (
                    <Copy className="h-3.5 w-3.5" />
                  )}
                </button>
              </div>

              <div className="flex items-center gap-2 self-end sm:self-auto">
                <button
                  type="button"
                  onClick={downloadJsonReport}
                  className="flex items-center gap-1.5 rounded-md border border-slate-200 bg-white px-2.5 py-1.5 text-xs font-medium text-slate-700 hover:bg-slate-50 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-300 dark:hover:bg-slate-700 shadow-2xs"
                >
                  <Download className="h-3.5 w-3.5" />
                  <span>Export JSON</span>
                </button>

                <button
                  type="button"
                  onClick={onReset}
                  className="flex items-center gap-1.5 rounded-md bg-slate-900 px-3 py-1.5 text-xs font-semibold text-white hover:bg-slate-800 dark:bg-sky-600 dark:hover:bg-sky-500 shadow-2xs"
                >
                  <RotateCcw className="h-3.5 w-3.5" />
                  <span>New Scan</span>
                </button>
              </div>
            </div>

            {/* Verdict Highlight Section */}
            <div className="mt-6 grid gap-6 lg:grid-cols-12 lg:items-center">
              {/* Verdict badge and commentary (7 cols) */}
              <div className="lg:col-span-7 space-y-3">
                <div className="flex flex-wrap items-center gap-2.5">
                  <div
                    className={`inline-flex items-center gap-1.5 rounded-lg px-3 py-1.5 text-sm font-bold tracking-wide uppercase ${
                      scanResult.verdict === "ADWARE"
                        ? "bg-amber-100 text-amber-900 border border-amber-300 dark:bg-amber-950/80 dark:text-amber-200 dark:border-amber-800"
                        : scanResult.verdict === "BENIGN"
                        ? "bg-emerald-100 text-emerald-900 border border-emerald-300 dark:bg-emerald-950/80 dark:text-emerald-200 dark:border-emerald-800"
                        : "bg-red-100 text-red-900 border border-red-300 dark:bg-red-950/80 dark:text-red-200 dark:border-red-800"
                    }`}
                  >
                    {scanResult.verdict === "ADWARE" ? (
                      <AlertTriangle className="h-4 w-4" />
                    ) : scanResult.verdict === "BENIGN" ? (
                      <ShieldCheck className="h-4 w-4" />
                    ) : (
                      <ShieldAlert className="h-4 w-4" />
                    )}
                    <span>{scanResult.verdict === "BENIGN" ? "BENIGN / VERIFIED CLEAN" : `${scanResult.verdict} DETECTED`}</span>
                  </div>

                  <span className="rounded-md bg-slate-100 px-2.5 py-1 text-xs font-semibold text-slate-700 dark:bg-slate-800 dark:text-slate-300">
                    Risk Level: {scanResult.risk_level}
                  </span>
                </div>

                <p className="text-sm leading-relaxed text-slate-700 dark:text-slate-300">
                  {scanResult.verdict === "ADWARE" ? (
                    <>
                      This application incorporates intrusive ad distribution patterns, foreground service persistence, and potential window overlay hijacking (<code className="font-mono text-xs font-semibold">SYSTEM_ALERT_WINDOW</code>).
                    </>
                  ) : scanResult.verdict === "BENIGN" ? (
                    <>
                      Static bytecode analysis found no aggressive commercial ad network hooks, shell injection routines, or dangerous privilege escalation chains.
                    </>
                  ) : (
                    <>
                      Critical malware threats detected. Bytecode analysis flagged root access commands, SMS exfiltration listeners, or staged dynamic payload downloaders.
                    </>
                  )}
                </p>

                <div className="flex flex-wrap items-center gap-4 text-xs text-slate-500 dark:text-slate-400 pt-1">
                  <span>Package Size: <strong>{scanResult.app_size_kb.toLocaleString()} KB</strong></span>
                  <span>&bull;</span>
                  <span>Model Confidence: <strong className="text-slate-900 dark:text-slate-100">{scanResult.confidence}%</strong></span>
                  <span>&bull;</span>
                  <span>Grounding: <strong>5 Corpuses</strong></span>
                </div>
              </div>

              {/* Class Probability Distribution Gauge (5 cols) */}
              <div className="lg:col-span-5 rounded-lg border border-slate-200/80 bg-slate-50 p-4 dark:border-slate-800 dark:bg-slate-800/50">
                <div className="text-xs font-semibold text-slate-700 dark:text-slate-300 mb-3 flex items-center justify-between">
                  <span>Calibrated Class Probabilities</span>
                  <span className="font-mono text-[11px] text-slate-500">Softmax Output</span>
                </div>

                <div className="space-y-2.5 text-xs">
                  {/* Benign */}
                  <div>
                    <div className="flex justify-between font-medium text-slate-700 dark:text-slate-300 mb-1">
                      <span>Benign (Safe)</span>
                      <span className="font-mono">{Math.max(0, scanResult.probabilities.Benign)}%</span>
                    </div>
                    <div className="h-2 w-full rounded-full bg-slate-200 dark:bg-slate-700 overflow-hidden">
                      <div
                        className="h-full bg-emerald-600 dark:bg-emerald-500 transition-all duration-500"
                        style={{ width: `${Math.max(0, Math.min(100, scanResult.probabilities.Benign))}%` }}
                      />
                    </div>
                  </div>

                  {/* Adware */}
                  <div>
                    <div className="flex justify-between font-medium text-slate-700 dark:text-slate-300 mb-1">
                      <span>Adware (Aggressive Ads)</span>
                      <span className="font-mono">{Math.max(0, scanResult.probabilities.Adware)}%</span>
                    </div>
                    <div className="h-2 w-full rounded-full bg-slate-200 dark:bg-slate-700 overflow-hidden">
                      <div
                        className="h-full bg-amber-600 dark:bg-amber-500 transition-all duration-500"
                        style={{ width: `${Math.max(0, Math.min(100, scanResult.probabilities.Adware))}%` }}
                      />
                    </div>
                  </div>

                  {/* Malware */}
                  <div>
                    <div className="flex justify-between font-medium text-slate-700 dark:text-slate-300 mb-1">
                      <span>Malware (Trojan / Exploit)</span>
                      <span className="font-mono">{Math.max(0, scanResult.probabilities.Malware)}%</span>
                    </div>
                    <div className="h-2 w-full rounded-full bg-slate-200 dark:bg-slate-700 overflow-hidden">
                      <div
                        className="h-full bg-red-600 dark:bg-red-500 transition-all duration-500"
                        style={{ width: `${Math.max(0, Math.min(100, scanResult.probabilities.Malware))}%` }}
                      />
                    </div>
                  </div>
                </div>
              </div>
            </div>

            {/* Quick Metrics Bar */}
            <div className="mt-6 grid grid-cols-2 gap-3 sm:grid-cols-4 pt-6 border-t border-slate-100 dark:border-slate-800/80 text-xs">
              <div className="rounded bg-slate-50 p-3 dark:bg-slate-800/40">
                <span className="text-slate-500">Declared Permissions</span>
                <div className="mt-1 font-mono text-lg font-bold text-slate-900 dark:text-slate-100">
                  {scanResult.feature_summary.total_permissions}
                </div>
              </div>
              <div className="rounded bg-slate-50 p-3 dark:bg-slate-800/40">
                <span className="text-slate-500">High-Risk Permissions</span>
                <div className="mt-1 font-mono text-lg font-bold text-amber-700 dark:text-amber-400">
                  {scanResult.feature_summary.high_risk_count}
                </div>
              </div>
              <div className="rounded bg-slate-50 p-3 dark:bg-slate-800/40">
                <span className="text-slate-500">Suspicious APIs Flagged</span>
                <div className="mt-1 font-mono text-lg font-bold text-slate-900 dark:text-slate-100">
                  {scanResult.feature_summary.api_calls_detected}
                </div>
              </div>
              <div className="rounded bg-slate-50 p-3 dark:bg-slate-800/40">
                <span className="text-slate-500">Ad SDKs Identified</span>
                <div className="mt-1 font-mono text-lg font-bold text-slate-900 dark:text-slate-100">
                  {scanResult.feature_summary.ad_sdks_detected}
                </div>
              </div>
            </div>
          </div>

          {/* Forensic Drilldown Tabs */}
          <div className="rounded-xl border border-slate-200 bg-white dark:border-slate-800 dark:bg-slate-900 transition-colors overflow-hidden">
            {/* Tab navigation */}
            <div className="flex border-b border-slate-200 px-6 pt-3 dark:border-slate-800 bg-slate-50/50 dark:bg-slate-800/40 gap-4">
              <button
                type="button"
                onClick={() => setActiveReportTab("permissions")}
                className={`pb-3 text-xs sm:text-sm font-medium border-b-2 transition-colors ${
                  activeReportTab === "permissions"
                    ? "border-slate-900 text-slate-900 dark:border-sky-400 dark:text-sky-300"
                    : "border-transparent text-slate-500 hover:text-slate-800 dark:text-slate-400 dark:hover:text-slate-200"
                }`}
              >
                Permission Risk &amp; Attention Weights
              </button>

              <button
                type="button"
                onClick={() => setActiveReportTab("apis")}
                className={`pb-3 text-xs sm:text-sm font-medium border-b-2 transition-colors ${
                  activeReportTab === "apis"
                    ? "border-slate-900 text-slate-900 dark:border-sky-400 dark:text-sky-300"
                    : "border-transparent text-slate-500 hover:text-slate-800 dark:text-slate-400 dark:hover:text-slate-200"
                }`}
              >
                DEX APIs &amp; Ad SDK Signatures
              </button>

              <button
                type="button"
                onClick={() => setActiveReportTab("summary")}
                className={`pb-3 text-xs sm:text-sm font-medium border-b-2 transition-colors ${
                  activeReportTab === "summary"
                    ? "border-slate-900 text-slate-900 dark:border-sky-400 dark:text-sky-300"
                    : "border-transparent text-slate-500 hover:text-slate-800 dark:text-slate-400 dark:hover:text-slate-200"
                }`}
              >
                Auditor Summary &amp; Citation Footnote
              </button>
            </div>

            {/* TAB 1 CONTENT: PERMISSIONS & ATTENTION ATTRIBUTION */}
            {activeReportTab === "permissions" && (
              <div className="p-6 space-y-6">
                <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
                  <div>
                    <h4 className="font-semibold text-slate-900 dark:text-slate-100 text-sm">
                      Manifest Permission Attributions
                    </h4>
                    <p className="text-xs text-slate-500 dark:text-slate-400">
                      Grounded in [1] and [5], attention weights represent how influential each permission was in triggering the verdict.
                    </p>
                  </div>

                  {/* Filter chips */}
                  <div className="flex items-center gap-1 self-start sm:self-auto">
                    {(["ALL", "HIGH", "MEDIUM"] as const).map((filter) => (
                      <button
                        key={filter}
                        type="button"
                        onClick={() => setPermissionFilter(filter)}
                        className={`rounded px-2.5 py-1 text-[11px] font-medium transition-colors ${
                          permissionFilter === filter
                            ? "bg-slate-900 text-white dark:bg-slate-700 dark:text-white"
                            : "bg-slate-100 text-slate-600 hover:bg-slate-200 dark:bg-slate-800 dark:text-slate-400"
                        }`}
                      >
                        {filter === "ALL" ? "All Detected" : `${filter} Risk`}
                      </button>
                    ))}
                  </div>
                </div>

                {/* Table of permissions */}
                <div className="overflow-x-auto rounded-lg border border-slate-200 dark:border-slate-800">
                  <table className="w-full text-left text-xs">
                    <thead className="bg-slate-50 border-b border-slate-200 text-slate-600 font-semibold dark:bg-slate-800/70 dark:border-slate-800 dark:text-slate-300">
                      <tr>
                        <th className="px-4 py-3">Permission Identifier</th>
                        <th className="px-3 py-3">Risk Tier</th>
                        <th className="px-3 py-3 text-right font-mono">Attention Weight</th>
                        <th className="px-4 py-3">Influence Meter</th>
                        <th className="px-4 py-3">Security Implication</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-100 dark:divide-slate-800/60">
                      {filteredPermissions.length === 0 ? (
                        <tr>
                          <td colSpan={5} className="px-4 py-6 text-center text-slate-500">
                            No permissions match the selected filter.
                          </td>
                        </tr>
                      ) : (
                        filteredPermissions.map((p, idx) => {
                          const explanation =
                            PERMISSION_EXPLANATIONS[p.name] ||
                            "Standard Android application capability requested in the package manifest.";
                          return (
                            <tr
                              key={idx}
                              className="hover:bg-slate-50/70 dark:hover:bg-slate-800/40 transition-colors"
                            >
                              <td className="px-4 py-3 font-mono font-semibold text-slate-900 dark:text-slate-100">
                                {p.name}
                              </td>
                              <td className="px-3 py-3">
                                <span
                                  className={`inline-block rounded px-2 py-0.5 text-[10px] font-bold ${
                                    p.risk === "HIGH"
                                      ? "bg-red-100 text-red-800 dark:bg-red-950/70 dark:text-red-300"
                                      : p.risk === "MEDIUM"
                                      ? "bg-amber-100 text-amber-800 dark:bg-amber-950/70 dark:text-amber-300"
                                      : "bg-slate-100 text-slate-700 dark:bg-slate-800 dark:text-slate-300"
                                  }`}
                                >
                                  {p.risk}
                                </span>
                              </td>
                              <td className="px-3 py-3 text-right font-mono text-slate-700 dark:text-slate-300">
                                {p.weight.toFixed(2)}
                              </td>
                              <td className="px-4 py-3 w-36">
                                <div className="h-1.5 w-full rounded-full bg-slate-100 dark:bg-slate-800 overflow-hidden">
                                  <div
                                    className={`h-full ${
                                      p.risk === "HIGH"
                                        ? "bg-red-600 dark:bg-red-500"
                                        : p.risk === "MEDIUM"
                                        ? "bg-amber-600 dark:bg-amber-500"
                                        : "bg-emerald-600 dark:bg-emerald-500"
                                    }`}
                                    style={{ width: `${p.percentage}%` }}
                                  />
                                </div>
                              </td>
                              <td className="px-4 py-3 text-slate-600 dark:text-slate-400 max-w-sm">
                                {explanation}
                              </td>
                            </tr>
                          );
                        })
                      )}
                    </tbody>
                  </table>
                </div>
              </div>
            )}

            {/* TAB 2 CONTENT: APIS & SDK SIGNATURES */}
            {activeReportTab === "apis" && (
              <div className="p-6 space-y-6">
                <div>
                  <h4 className="font-semibold text-slate-900 dark:text-slate-100 text-sm">
                    Dalvik DEX Bytecode Symbols &amp; Third-Party Networks
                  </h4>
                  <p className="text-xs text-slate-500 dark:text-slate-400">
                    Static inspection of classes.dex string tables for suspicious invocation APIs and aggressive ad networks.
                  </p>
                </div>

                <div className="grid gap-6 md:grid-cols-2">
                  {/* Suspicious APIs */}
                  <div className="rounded-lg border border-slate-200 p-4 dark:border-slate-800">
                    <div className="flex items-center gap-2 font-medium text-slate-900 dark:text-slate-200 text-xs uppercase tracking-wider mb-3">
                      <Code className="h-4 w-4 text-sky-600 dark:text-sky-400" />
                      Suspicious API Calls
                    </div>

                    <div className="space-y-2">
                      {scanResult.suspicious_apis.map((api, idx) => (
                        <div
                          key={idx}
                          className="flex items-start gap-2 rounded bg-slate-50 p-2.5 text-xs dark:bg-slate-800/50"
                        >
                          <ChevronRight className="h-3.5 w-3.5 shrink-0 text-slate-400 mt-0.5" />
                          <span className="font-mono text-slate-800 dark:text-slate-200">{api}</span>
                        </div>
                      ))}
                    </div>
                  </div>

                  {/* Ad SDKs */}
                  <div className="rounded-lg border border-slate-200 p-4 dark:border-slate-800">
                    <div className="flex items-center gap-2 font-medium text-slate-900 dark:text-slate-200 text-xs uppercase tracking-wider mb-3">
                      <Layers className="h-4 w-4 text-sky-600 dark:text-sky-400" />
                      Detected Commercial Ad Networks
                    </div>

                    <div className="space-y-2">
                      {scanResult.ad_sdks.length > 0 ? (
                        scanResult.ad_sdks.map((sdk, idx) => (
                          <div
                            key={idx}
                            className="flex items-center justify-between rounded bg-slate-50 p-2.5 text-xs dark:bg-slate-800/50"
                          >
                            <span className="font-medium text-slate-800 dark:text-slate-200">
                              {sdk}
                            </span>
                            <span className="rounded bg-amber-100 px-2 py-0.5 text-[10px] font-bold text-amber-800 dark:bg-amber-950/70 dark:text-amber-300">
                              Commercial SDK
                            </span>
                          </div>
                        ))
                      ) : (
                        <div className="text-xs text-slate-500 p-3 italic">
                          No known commercial ad SDK footprints detected in DEX string pool.
                        </div>
                      )}
                    </div>
                  </div>
                </div>
              </div>
            )}

            {/* TAB 3 CONTENT: AUDITOR SUMMARY & CITATIONS */}
            {activeReportTab === "summary" && (
              <div className="p-6 space-y-6">
                <div>
                  <h4 className="font-semibold text-slate-900 dark:text-slate-100 text-sm">
                    Auditor Summary &amp; Model Grounding Note
                  </h4>
                  <p className="text-xs text-slate-500 dark:text-slate-400">
                    Academic grounding and formal notes for inclusion in security audit documentation.
                  </p>
                </div>

                <div className="rounded-lg border border-slate-200 bg-slate-50 p-4 dark:border-slate-800 dark:bg-slate-800/50 space-y-3 text-xs leading-relaxed text-slate-700 dark:text-slate-300">
                  <p>
                    <strong>Formal Assessment:</strong> The package <code className="font-mono text-slate-900 dark:text-slate-100 font-bold">{scanResult.package_name}</code> was evaluated using a 360-dimensional multimodal feature map grounded in 73,109 samples from 5 benchmark datasets (CICMalDroid 2020, CICAndMal2017, Drebin, AndroZoo, MalGenome).
                  </p>
                  <p>
                    <strong>Classification Verdict:</strong> {scanResult.verdict} with {scanResult.confidence}% confidence. Primary contributing vectors include {scanResult.feature_summary.high_risk_count} high-risk permissions and {scanResult.feature_summary.ad_sdks_detected} third-party ad SDK binaries.
                  </p>
                  <div className="pt-2 border-t border-slate-200 dark:border-slate-700 flex items-center justify-between">
                    <span className="text-[11px] text-slate-500">
                      Engine Reference: AdwareGuard v1.0 per Ullah et al. [1] &amp; Almakayeel [2]
                    </span>
                    <button
                      type="button"
                      onClick={() =>
                        copyToClipboard(
                          `Package: ${scanResult.package_name}\nVerdict: ${scanResult.verdict} (${scanResult.confidence}%)\nHigh-risk Permissions: ${scanResult.feature_summary.high_risk_count}\nAd SDKs: ${scanResult.ad_sdks.join(", ")}`,
                          "summary"
                        )
                      }
                      className="flex items-center gap-1 text-[11px] font-medium text-slate-700 hover:text-slate-900 dark:text-slate-300 dark:hover:text-white"
                    >
                      {copiedSummary ? <Check className="h-3 w-3 text-emerald-600" /> : <Copy className="h-3 w-3" />}
                      <span>{copiedSummary ? "Summary Copied" : "Copy Briefing Note"}</span>
                    </button>
                  </div>
                </div>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
};
