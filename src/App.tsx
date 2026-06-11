/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import { useState, useEffect, useRef, useCallback, useReducer } from "react";
import {
  Github,
  Upload,
  CheckCircle2,
  Loader2,
  LogOut,
  Archive,
  FolderGit2,
  ExternalLink,
  AlertCircle,
  RefreshCw,
} from "lucide-react";
import { motion, AnimatePresence } from "motion/react";

// ─────────────────────────────────────────────────────────────────────────────
// Constants
// ─────────────────────────────────────────────────────────────────────────────
const MAX_FILE_SIZE_MB = 50;
const MAX_FILE_SIZE_BYTES = MAX_FILE_SIZE_MB * 1024 * 1024;

// How long to wait before automatically resetting a stuck "Connecting…" state.
// A real OAuth flow completes in seconds; 2 minutes is ample while avoiding
// leaving the button disabled indefinitely if the user closes the popup.
const CONNECT_TIMEOUT_MS = 2 * 60 * 1000;

// ─────────────────────────────────────────────────────────────────────────────
// Types
// ─────────────────────────────────────────────────────────────────────────────
interface Repo {
  id: number;
  full_name: string;
  private: boolean;
}

type UploadStatus = "idle" | "uploading" | "success" | "error";

interface AppState {
  /** GitHub OAuth access token — kept only in React state (never localStorage). */
  token: string | null;
  repos: Repo[];
  selectedRepo: string;
  selectedFile: File | null;
  uploadStatus: UploadStatus;
  statusMessage: string;
  commitUrl: string | null;
  isLoadingRepos: boolean;
  repoError: string | null;
  isDragOver: boolean;
  isConnecting: boolean;
}

type AppAction =
  | { type: "SET_TOKEN"; token: string }
  | { type: "CLEAR_SESSION" }
  | { type: "REPOS_LOADING" }
  | { type: "REPOS_LOADED"; repos: Repo[] }
  | { type: "REPOS_ERROR"; message: string }
  | { type: "SELECT_REPO"; repo: string }
  | { type: "SELECT_FILE"; file: File }
  | { type: "CLEAR_FILE" }
  | { type: "UPLOAD_START" }
  | { type: "UPLOAD_SUCCESS"; message: string; url: string }
  | { type: "UPLOAD_ERROR"; message: string }
  | { type: "SET_DRAG_OVER"; over: boolean }
  | { type: "SET_CONNECTING"; connecting: boolean };

const initialState: AppState = {
  token: null,
  repos: [],
  selectedRepo: "",
  selectedFile: null,
  uploadStatus: "idle",
  statusMessage: "",
  commitUrl: null,
  isLoadingRepos: false,
  repoError: null,
  isDragOver: false,
  isConnecting: false,
};

function reducer(state: AppState, action: AppAction): AppState {
  switch (action.type) {
    case "SET_TOKEN":
      return { ...state, token: action.token, isConnecting: false };
    case "CLEAR_SESSION":
      return { ...initialState };
    case "REPOS_LOADING":
      return { ...state, isLoadingRepos: true, repos: [], repoError: null };
    case "REPOS_LOADED":
      return { ...state, isLoadingRepos: false, repos: action.repos };
    case "REPOS_ERROR":
      return { ...state, isLoadingRepos: false, repoError: action.message };
    case "SELECT_REPO":
      return { ...state, selectedRepo: action.repo };
    case "SELECT_FILE":
      return {
        ...state,
        selectedFile: action.file,
        uploadStatus: "idle",
        commitUrl: null,
        statusMessage: "",
      };
    case "CLEAR_FILE":
      return { ...state, selectedFile: null, uploadStatus: "idle", commitUrl: null, statusMessage: "" };
    case "UPLOAD_START":
      return { ...state, uploadStatus: "uploading", statusMessage: "Extracting and pushing to GitHub…", commitUrl: null };
    case "UPLOAD_SUCCESS":
      return { ...state, uploadStatus: "success", statusMessage: action.message, commitUrl: action.url };
    case "UPLOAD_ERROR":
      return { ...state, uploadStatus: "error", statusMessage: action.message };
    case "SET_DRAG_OVER":
      return { ...state, isDragOver: action.over };
    case "SET_CONNECTING":
      return { ...state, isConnecting: action.connecting };
    default:
      return state;
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Utility
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Returns true if the given string is a trusted OAuth origin.
 * Checks protocol explicitly so a non-http(s) URL whose hostname happens to be
 * "localhost" (e.g. "javascript://localhost") cannot pass validation.
 */
function isTrustedOrigin(origin: string): boolean {
  try {
    const { protocol, hostname } = new URL(origin);
    const isLocalhost = hostname === "localhost" || hostname === "127.0.0.1";
    const isCloudRun = /^[a-z0-9-]+\.run\.app$/.test(hostname);

    if (isLocalhost) return protocol === "http:" || protocol === "https:";
    if (isCloudRun) return protocol === "https:";
    return false;
  } catch {
    return false;
  }
}

/**
 * FIX F: Validates that the URL returned by /api/auth/url is actually a
 * GitHub OAuth URL before opening it in a popup. This prevents a compromised
 * or MITM'd response from redirecting the user to a phishing page or executing
 * javascript: / data: URIs via window.open().
 */
function isValidGitHubOAuthUrl(url: string): boolean {
  try {
    const parsed = new URL(url);
    return (
      parsed.protocol === "https:" &&
      parsed.hostname === "github.com" &&
      parsed.pathname === "/login/oauth/authorize"
    );
  } catch {
    return false;
  }
}

/** Validate a file, returning an error string or null. */
function validateFile(file: File): string | null {
  if (!file.name.toLowerCase().endsWith(".zip")) {
    return "Only .zip files are accepted.";
  }
  if (file.size > MAX_FILE_SIZE_BYTES) {
    return `File exceeds the ${MAX_FILE_SIZE_MB} MB limit.`;
  }
  if (file.size === 0) {
    return "The selected file is empty.";
  }
  return null;
}

// ─────────────────────────────────────────────────────────────────────────────
// Component
// ─────────────────────────────────────────────────────────────────────────────
export default function App() {
  const [state, dispatch] = useReducer(reducer, initialState);
  const fileInputRef = useRef<HTMLInputElement>(null);

  // AbortController ref for cancelling in-flight upload on unmount
  const uploadAbortRef = useRef<AbortController | null>(null);

  // fetchRepos needs its own AbortController so that if the token
  // changes quickly (edge case) or the component unmounts mid-fetch, the stale
  // request is cancelled instead of overwriting newer state.
  const fetchAbortRef = useRef<AbortController | null>(null);

  // Keep a ref to the connect-timeout timer so it can be cleared on
  // successful auth or on component unmount, preventing a setState-on-unmounted
  // component warning and avoiding a spurious re-enable of the button.
  const connectTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  const {
    token, repos, selectedRepo, selectedFile,
    uploadStatus, statusMessage, commitUrl,
    isLoadingRepos, repoError, isDragOver, isConnecting,
  } = state;

  const isUploading = uploadStatus === "uploading";

  // ── Cleanup on unmount ──────────────────────────────────────────────────
  useEffect(() => {
    return () => {
      uploadAbortRef.current?.abort();
      fetchAbortRef.current?.abort();
      if (connectTimerRef.current !== null) {
        clearTimeout(connectTimerRef.current);
      }
    };
  }, []);

  // ── Prevent the browser from opening a dropped file as a new page.
  // When the user drags a file and misses the drop zone, the browser's default
  // behaviour is to navigate to / display the file. Intercept dragover and drop
  // on the window to stop that while still allowing our drop zone to work.
  useEffect(() => {
    const preventBrowserDrop = (e: DragEvent) => {
      e.preventDefault();
    };
    window.addEventListener("dragover", preventBrowserDrop);
    window.addEventListener("drop", preventBrowserDrop);
    return () => {
      window.removeEventListener("dragover", preventBrowserDrop);
      window.removeEventListener("drop", preventBrowserDrop);
    };
  }, []);

  // ── OAuth popup message listener ────────────────────────────────────────
  useEffect(() => {
    const handleMessage = (event: MessageEvent) => {
      // Only accept messages from the same origin or a trusted Cloud Run domain.
      if (
        event.origin !== window.location.origin &&
        !isTrustedOrigin(event.origin)
      ) {
        return;
      }
      if (event.data?.type === "OAUTH_AUTH_SUCCESS") {
        const t = event.data.token;
        if (typeof t === "string" && t.length > 0) {
          if (connectTimerRef.current !== null) {
            clearTimeout(connectTimerRef.current);
            connectTimerRef.current = null;
          }
          dispatch({ type: "SET_TOKEN", token: t });
        }
      }
    };

    window.addEventListener("message", handleMessage);
    return () => window.removeEventListener("message", handleMessage);
  }, []);

  // ── Fetch repos whenever we get a valid token ───────────────────────────
  const fetchRepos = useCallback(async (currentToken: string) => {
    // Cancel any in-flight repo fetch before starting a new one.
    fetchAbortRef.current?.abort();
    const controller = new AbortController();
    fetchAbortRef.current = controller;

    dispatch({ type: "REPOS_LOADING" });
    try {
      const response = await fetch("/api/github/repos", {
        headers: { Authorization: `Bearer ${currentToken}` },
        signal: controller.signal,
      });

      if (!response.ok) {
        if (response.status === 401) {
          dispatch({ type: "CLEAR_SESSION" });
          return;
        }
        const body = await response.json().catch(() => ({}));
        throw new Error((body as { error?: string }).error ?? "Failed to fetch repositories");
      }

      const data: Repo[] = await response.json();
      dispatch({ type: "REPOS_LOADED", repos: data });
    } catch (error: unknown) {
      // AbortError means a newer fetch superseded this one — silently discard.
      if (error instanceof Error && error.name === "AbortError") return;
      const message = error instanceof Error ? error.message : "Could not load repositories";
      dispatch({ type: "REPOS_ERROR", message });
    }
  }, []);

  useEffect(() => {
    if (token) fetchRepos(token);
  }, [token, fetchRepos]);

  // ── Auth handlers ───────────────────────────────────────────────────────
  const handleConnect = async () => {
    if (isConnecting) return;
    dispatch({ type: "SET_CONNECTING", connecting: true });

    try {
      const redirectUri = `${window.location.origin}/auth/callback`;
      const response = await fetch(
        `/api/auth/url?redirectUri=${encodeURIComponent(redirectUri)}`
      );
      if (!response.ok) throw new Error("Failed to get auth URL");
      const { url } = await response.json() as { url: string };

      // FIX F applied: Validate the returned URL is genuinely a GitHub OAuth
      // URL before opening it. Prevents a malicious / MITM response from
      // opening a javascript: URI or a phishing page in the popup.
      if (!isValidGitHubOAuthUrl(url)) {
        dispatch({ type: "SET_CONNECTING", connecting: false });
        dispatch({
          type: "UPLOAD_ERROR",
          message: "Received an unexpected authentication URL. Please try again.",
        });
        return;
      }

      // FIX G: "noopener=no" does NOT set the noopener feature in Chromium —
      // the string "no" is a truthy value, so the feature is treated as present
      // with the value "no", which Chromium ignores, leaving window.opener
      // accessible. The correct approach is to omit "noopener" entirely from
      // the features string when we NEED opener access for postMessage, OR to
      // use "noopener" (without "=no") when we don't. Since the OAuth popup
      // must postMessage back to window.opener, we deliberately omit "noopener"
      // here so that opener is accessible. The security boundary is enforced by
      // the origin-check in the message listener and the CSP on the callback page.
      const popup = window.open(url, "oauth_popup", "width=600,height=700");
      if (!popup) {
        // When popup is blocked, don't set the timer — return immediately.
        dispatch({ type: "SET_CONNECTING", connecting: false });
        dispatch({
          type: "UPLOAD_ERROR",
          message: "Pop-ups are blocked. Please allow pop-ups for this site and try again.",
        });
        return;
      }

      // Store the timer ref so it can be cancelled on success or unmount.
      connectTimerRef.current = setTimeout(() => {
        connectTimerRef.current = null;
        dispatch({ type: "SET_CONNECTING", connecting: false });
      }, CONNECT_TIMEOUT_MS);
    } catch (error: unknown) {
      dispatch({ type: "SET_CONNECTING", connecting: false });
      const message = error instanceof Error ? error.message : "Failed to initiate GitHub login.";
      dispatch({ type: "UPLOAD_ERROR", message });
    }
  };

  // ── File handlers ───────────────────────────────────────────────────────
  const acceptFile = useCallback((file: File) => {
    const error = validateFile(file);
    if (error) {
      dispatch({ type: "UPLOAD_ERROR", message: error });
      return;
    }
    dispatch({ type: "SELECT_FILE", file });
  }, []);

  const handleFileDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    dispatch({ type: "SET_DRAG_OVER", over: false });
    const file = e.dataTransfer.files?.[0];
    if (file) acceptFile(file);
  }, [acceptFile]);

  const handleFileSelect = useCallback((e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (file) acceptFile(file);
    e.target.value = ""; // allow re-selecting the same file
  }, [acceptFile]);

  // Drag leave — only clear when the drag has left the drop zone entirely
  const handleDragLeave = useCallback((e: React.DragEvent) => {
    if (!e.currentTarget.contains(e.relatedTarget as Node | null)) {
      dispatch({ type: "SET_DRAG_OVER", over: false });
    }
  }, []);

  // ── Upload ──────────────────────────────────────────────────────────────
  const handleUpload = async () => {
    if (!selectedFile || !selectedRepo || !token || isUploading) return;

    const slashIdx = selectedRepo.indexOf("/");
    if (slashIdx === -1) {
      dispatch({ type: "UPLOAD_ERROR", message: "Invalid repository format" });
      return;
    }
    const owner = selectedRepo.slice(0, slashIdx);
    const repo = selectedRepo.slice(slashIdx + 1);

    // Cancel any previous in-flight request
    uploadAbortRef.current?.abort();
    const controller = new AbortController();
    uploadAbortRef.current = controller;

    dispatch({ type: "UPLOAD_START" });

    const formData = new FormData();
    formData.append("file", selectedFile);
    formData.append("owner", owner);
    formData.append("repo", repo);
    // FIX H: The branch field was never included in the FormData payload, so
    // the server always fell back to the "main" default regardless of any
    // branch the user might expect. Since the UI currently has no branch
    // selector, we send "main" explicitly — this makes the contract clear and
    // means a future branch selector only needs to update this one line.
    formData.append("branch", "main");
    formData.append("commitMessage", `Update from Zip Sync (${selectedFile.name})`);

    try {
      const response = await fetch("/api/github/push", {
        method: "POST",
        headers: { Authorization: `Bearer ${token}` },
        body: formData,
        signal: controller.signal,
      });

      const data = await response.json() as { url?: string; branchUrl?: string; error?: string };

      if (response.ok) {
        dispatch({
          type: "UPLOAD_SUCCESS",
          message: `Successfully pushed to ${selectedRepo}`,
          // FIX E applied: use the specific commit URL (immutable) rather than
          // the branch URL. The server now returns both; prefer commit URL.
          url: data.url ?? data.branchUrl ?? "",
        });
      } else {
        dispatch({
          type: "UPLOAD_ERROR",
          message: data.error ?? "Failed to push to GitHub",
        });
      }
    } catch (error: unknown) {
      if (error instanceof Error && error.name === "AbortError") return;
      const message = error instanceof Error ? error.message : "An unexpected error occurred";
      dispatch({ type: "UPLOAD_ERROR", message });
    }
  };

  // ─────────────────────────────────────────────────────────────────────────
  // Render
  // ─────────────────────────────────────────────────────────────────────────
  return (
    <div className="min-h-screen bg-gray-50 flex items-center justify-center p-4">
      <div className="w-full max-w-lg bg-white rounded-2xl shadow-xl shadow-gray-200/50 overflow-hidden">

        {/* ── Header ─────────────────────────────────────────────────────── */}
        <div className="p-8 border-b border-gray-100 bg-gray-900 text-white text-center">
          <div className="mx-auto w-12 h-12 bg-white/10 rounded-full flex items-center justify-center mb-4 ring-4 ring-white/5">
            <Github className="w-6 h-6 text-white" />
          </div>
          <h1 className="text-2xl font-semibold tracking-tight">GitHub Zip Sync</h1>
          <p className="text-gray-400 mt-2 text-sm max-w-sm mx-auto">
            Upload your AI Studio ZIP exports and push them directly to your repositories.
          </p>
        </div>

        {/* ── Body ───────────────────────────────────────────────────────── */}
        <div className="p-8">
          <AnimatePresence mode="wait">

            {/* ── Not connected ─────────────────────────────────────────── */}
            {!token ? (
              <motion.div
                key="login"
                initial={{ opacity: 0, y: 10 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, y: -10 }}
                className="text-center py-6"
              >
                <p className="text-gray-600 text-sm mb-6">
                  Connect your GitHub account to push ZIP contents directly to
                  your repositories — no local Git environment needed.
                </p>

                {/* Inline error banner on the login screen */}
                {uploadStatus === "error" && statusMessage && (
                  <div className="mb-4 p-3 rounded-lg text-sm bg-red-50 text-red-800 border border-red-100 flex items-center gap-2 text-left">
                    <AlertCircle className="w-4 h-4 shrink-0" />
                    <span>{statusMessage}</span>
                  </div>
                )}

                <button
                  onClick={handleConnect}
                  disabled={isConnecting}
                  className="inline-flex items-center justify-center gap-2 w-full px-6 py-3 bg-gray-900 text-white font-medium rounded-lg hover:bg-gray-800 disabled:opacity-60 disabled:cursor-not-allowed transition-colors focus:ring-4 focus:ring-gray-200 outline-none"
                >
                  {isConnecting ? (
                    <>
                      <Loader2 className="w-5 h-5 animate-spin" />
                      Connecting…
                    </>
                  ) : (
                    <>
                      <Github className="w-5 h-5" />
                      Connect GitHub
                    </>
                  )}
                </button>
              </motion.div>

            ) : (
              /* ── Connected dashboard ──────────────────────────────────── */
              <motion.div
                key="dashboard"
                initial={{ opacity: 0, y: 10 }}
                animate={{ opacity: 1, y: 0 }}
                className="space-y-6"
              >
                {/* Repository selector */}
                <div className="space-y-2">
                  <div className="flex items-center justify-between">
                    <label className="text-sm font-medium text-gray-700 flex items-center gap-2">
                      <FolderGit2 className="w-4 h-4 text-gray-400" />
                      Select Repository
                    </label>
                    <div className="flex items-center gap-3">
                      {repoError && (
                        <button
                          onClick={() => fetchRepos(token)}
                          className="text-xs text-gray-400 hover:text-gray-700 flex items-center gap-1 transition-colors"
                          title="Retry loading repositories"
                        >
                          <RefreshCw className="w-3 h-3" />
                          Retry
                        </button>
                      )}
                      <button
                        onClick={() => dispatch({ type: "CLEAR_SESSION" })}
                        className="text-xs text-gray-400 hover:text-red-500 flex items-center gap-1 transition-colors"
                      >
                        <LogOut className="w-3 h-3" />
                        Disconnect
                      </button>
                    </div>
                  </div>

                  {repoError ? (
                    <div className="p-3 rounded-lg text-sm bg-red-50 text-red-800 border border-red-100 flex items-center gap-2">
                      <AlertCircle className="w-4 h-4 shrink-0" />
                      <span>{repoError}</span>
                    </div>
                  ) : (
                    <div className="relative">
                      <select
                        value={selectedRepo}
                        onChange={(e) => dispatch({ type: "SELECT_REPO", repo: e.target.value })}
                        disabled={isLoadingRepos || isUploading}
                        className="w-full pl-3 pr-10 py-3 bg-gray-50 border border-gray-200 rounded-lg appearance-none text-gray-900 focus:outline-none focus:ring-2 focus:ring-gray-900 focus:border-transparent transition-all disabled:opacity-50"
                      >
                        <option value="" disabled>
                          {isLoadingRepos ? "Loading repositories…" : "Choose a repository…"}
                        </option>
                        {repos.map((r) => (
                          <option key={r.id} value={r.full_name}>
                            {r.full_name}
                          </option>
                        ))}
                      </select>
                      <div className="absolute inset-y-0 right-3 flex items-center pointer-events-none">
                        {isLoadingRepos ? (
                          <Loader2 className="w-4 h-4 text-gray-400 animate-spin" />
                        ) : (
                          <ChevronDownIcon className="w-4 h-4 text-gray-400" />
                        )}
                      </div>
                    </div>
                  )}
                </div>

                {/* Drop zone */}
                <div className="space-y-2">
                  <label className="text-sm font-medium text-gray-700 flex items-center gap-2">
                    <Archive className="w-4 h-4 text-gray-400" />
                    ZIP Archive{" "}
                    <span className="text-gray-400 font-normal">(max {MAX_FILE_SIZE_MB} MB)</span>
                  </label>

                  <div
                    role="button"
                    tabIndex={0}
                    aria-label="Click to select a ZIP file or drag and drop"
                    onDragOver={(e) => { e.preventDefault(); dispatch({ type: "SET_DRAG_OVER", over: true }); }}
                    onDragLeave={handleDragLeave}
                    onDrop={handleFileDrop}
                    onClick={() => !isUploading && fileInputRef.current?.click()}
                    onKeyDown={(e) => { if (e.key === "Enter" || e.key === " ") fileInputRef.current?.click(); }}
                    className={[
                      "border-2 border-dashed rounded-xl p-8 text-center transition-colors cursor-pointer select-none",
                      "focus:outline-none focus-visible:ring-2 focus-visible:ring-gray-900",
                      isUploading ? "opacity-50 pointer-events-none" : "",
                      isDragOver
                        ? "border-gray-500 bg-gray-100"
                        : selectedFile
                        ? "border-gray-900 bg-gray-50"
                        : "border-gray-200 hover:border-gray-300 hover:bg-gray-50",
                    ].join(" ")}
                  >
                    <input
                      type="file"
                      ref={fileInputRef}
                      onChange={handleFileSelect}
                      accept=".zip"
                      className="hidden"
                    />

                    {selectedFile ? (
                      <div className="flex flex-col items-center gap-2">
                        <div className="w-10 h-10 bg-gray-900 rounded-full flex items-center justify-center text-white mb-2">
                          <CheckCircle2 className="w-5 h-5" />
                        </div>
                        <p className="text-gray-900 font-medium truncate max-w-full px-4">
                          {selectedFile.name}
                        </p>
                        <p className="text-gray-500 text-xs">
                          {(selectedFile.size / 1024 / 1024).toFixed(2)} MB
                        </p>
                      </div>
                    ) : (
                      <div className="flex flex-col items-center gap-2">
                        <div className="w-12 h-12 bg-gray-100 rounded-full flex items-center justify-center text-gray-500 mb-2">
                          <Upload className="w-6 h-6" />
                        </div>
                        <p className="text-gray-900 font-medium">
                          Click to upload or drag and drop
                        </p>
                        <p className="text-gray-400 text-sm">Valid .zip archive</p>
                      </div>
                    )}
                  </div>
                </div>

                {/* Status banner */}
                <AnimatePresence>
                  {uploadStatus !== "idle" && (
                    <motion.div
                      key={uploadStatus}
                      initial={{ opacity: 0, height: 0 }}
                      animate={{ opacity: 1, height: "auto" }}
                      exit={{ opacity: 0, height: 0 }}
                      className={[
                        "p-4 rounded-lg text-sm flex items-start gap-3 overflow-hidden",
                        uploadStatus === "success"
                          ? "bg-green-50 text-green-900 border border-green-100"
                          : uploadStatus === "error"
                          ? "bg-red-50 text-red-900 border border-red-100"
                          : "bg-blue-50 text-blue-900 border border-blue-100",
                      ].join(" ")}
                    >
                      {uploadStatus === "success" ? (
                        <CheckCircle2 className="w-5 h-5 text-green-600 shrink-0 mt-0.5" />
                      ) : uploadStatus === "uploading" ? (
                        <Loader2 className="w-5 h-5 text-blue-600 shrink-0 mt-0.5 animate-spin" />
                      ) : (
                        <AlertCircle className="w-5 h-5 text-red-600 shrink-0 mt-0.5" />
                      )}
                      <div className="flex-1 min-w-0">
                        <p className="break-words">{statusMessage}</p>
                        {commitUrl && (
                          <a
                            href={commitUrl}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="inline-flex items-center gap-1 mt-1 text-green-700 underline underline-offset-2 hover:text-green-800"
                          >
                            View on GitHub <ExternalLink className="w-3 h-3" />
                          </a>
                        )}
                      </div>
                    </motion.div>
                  )}
                </AnimatePresence>

                {/* Push button */}
                <button
                  onClick={handleUpload}
                  disabled={!selectedFile || !selectedRepo || isUploading}
                  className="w-full flex items-center justify-center gap-2 px-6 py-3 bg-gray-900 text-white font-medium rounded-lg hover:bg-gray-800 disabled:opacity-50 disabled:cursor-not-allowed transition-all focus:ring-4 focus:ring-gray-200 outline-none"
                >
                  {isUploading ? (
                    <>
                      <Loader2 className="w-5 h-5 animate-spin" />
                      Pushing to GitHub…
                    </>
                  ) : (
                    "Push to GitHub"
                  )}
                </button>
              </motion.div>
            )}
          </AnimatePresence>
        </div>
      </div>
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// Helper component
// ─────────────────────────────────────────────────────────────────────────────
function ChevronDownIcon({ className }: { className?: string }) {
  return (
    <svg
      xmlns="http://www.w3.org/2000/svg"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
      className={className}
      aria-hidden="true"
    >
      <path d="m6 9 6 6 6-6" />
    </svg>
  );
}
