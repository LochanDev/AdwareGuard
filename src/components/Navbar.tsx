import React from "react";
import { Shield, Sun, Moon, Database, Cpu, Activity } from "lucide-react";

interface NavbarProps {
  activeTab: "scanner" | "datasets" | "model";
  setActiveTab: (tab: "scanner" | "datasets" | "model") => void;
  isDarkMode: boolean;
  toggleTheme: () => void;
}

export const Navbar: React.FC<NavbarProps> = ({
  activeTab,
  setActiveTab,
  isDarkMode,
  toggleTheme,
}) => {
  return (
    <header className="sticky top-0 z-40 border-b border-slate-200 bg-white/95 backdrop-blur-sm dark:border-slate-800 dark:bg-slate-900/95 transition-colors">
      <div className="mx-auto flex h-16 max-w-7xl items-center justify-between px-4 sm:px-6 lg:px-8">
        {/* Brand identity */}
        <div className="flex items-center gap-3">
          <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-slate-900 text-white shadow-sm dark:bg-slate-800 dark:text-sky-400 border border-slate-700/50">
            <Shield className="h-5 w-5" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <span className="font-semibold tracking-tight text-slate-900 dark:text-slate-100 text-lg">
                AdwareGuard
              </span>
              <span className="rounded bg-slate-100 px-1.5 py-0.5 font-mono text-[11px] font-medium text-slate-600 dark:bg-slate-800 dark:text-slate-400">
                v1.0-ML
              </span>
            </div>
            <p className="text-xs text-slate-500 dark:text-slate-400 hidden sm:block">
              Android Security &amp; Multimodal Attention Engine
            </p>
          </div>
        </div>

        {/* Center / Navigation Tabs */}
        <nav className="flex items-center gap-1 rounded-lg bg-slate-100 p-1 dark:bg-slate-800/80 border border-slate-200/80 dark:border-slate-700/50">
          <button
            type="button"
            onClick={() => setActiveTab("scanner")}
            className={`flex items-center gap-1.5 rounded-md px-3 py-1.5 text-xs sm:text-sm font-medium transition-all ${
              activeTab === "scanner"
                ? "bg-white text-slate-900 shadow-xs dark:bg-slate-700 dark:text-white"
                : "text-slate-600 hover:text-slate-900 dark:text-slate-400 dark:hover:text-white"
            }`}
          >
            <Activity className="h-4 w-4" />
            <span>Inspection Console</span>
          </button>

          <button
            type="button"
            onClick={() => setActiveTab("datasets")}
            className={`flex items-center gap-1.5 rounded-md px-3 py-1.5 text-xs sm:text-sm font-medium transition-all ${
              activeTab === "datasets"
                ? "bg-white text-slate-900 shadow-xs dark:bg-slate-700 dark:text-white"
                : "text-slate-600 hover:text-slate-900 dark:text-slate-400 dark:hover:text-white"
            }`}
          >
            <Database className="h-4 w-4" />
            <span>Benchmarks (5)</span>
          </button>

          <button
            type="button"
            onClick={() => setActiveTab("model")}
            className={`flex items-center gap-1.5 rounded-md px-3 py-1.5 text-xs sm:text-sm font-medium transition-all ${
              activeTab === "model"
                ? "bg-white text-slate-900 shadow-xs dark:bg-slate-700 dark:text-white"
                : "text-slate-600 hover:text-slate-900 dark:text-slate-400 dark:hover:text-white"
            }`}
          >
            <Cpu className="h-4 w-4" />
            <span>Architecture &amp; Citations</span>
          </button>
        </nav>

        {/* Right tools / System state & Theme Switch */}
        <div className="flex items-center gap-3">
          <div className="hidden lg:flex items-center gap-2 rounded-full border border-emerald-200 bg-emerald-50/80 px-2.5 py-1 text-xs font-medium text-emerald-800 dark:border-emerald-900/60 dark:bg-emerald-950/40 dark:text-emerald-300">
            <span className="relative flex h-2 w-2">
              <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-emerald-400 opacity-75"></span>
              <span className="relative inline-flex h-2 w-2 rounded-full bg-emerald-500"></span>
            </span>
            <span>Transformer Ready</span>
          </div>

          <button
            type="button"
            onClick={toggleTheme}
            aria-label="Toggle theme"
            title={isDarkMode ? "Switch to light theme" : "Switch to dark theme"}
            className="flex h-9 w-9 items-center justify-center rounded-lg border border-slate-200 bg-white text-slate-700 hover:bg-slate-50 hover:text-slate-900 dark:border-slate-800 dark:bg-slate-800 dark:text-slate-300 dark:hover:bg-slate-700 dark:hover:text-white transition-colors"
          >
            {isDarkMode ? <Sun className="h-4 w-4" /> : <Moon className="h-4 w-4" />}
          </button>
        </div>
      </div>
    </header>
  );
};
