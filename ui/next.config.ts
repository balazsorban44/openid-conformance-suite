import { resolve } from "node:path";
import type { NextConfig } from "next";

// the UI imports the plans and projects from the suite (../src/runner/projects.ts)
const repoRoot = resolve(import.meta.dirname, "..");

const nextConfig: NextConfig = {
	turbopack: { root: repoRoot },
	outputFileTracingRoot: repoRoot,
	// the hosted (read-only) UI reads ui/sample-data at run time (lib/paths.ts): the path is computed, so the file
	// tracer cannot see it. Every route that reads results ships the directory (relative to this directory).
	outputFileTracingIncludes: {
		"/**": ["./sample-data/**/*"],
	},
	devIndicators: false,
	// the repository's CLAUDE.md and .claude/skills are the agent instructions; no generated ui/AGENTS.md
	agentRules: false,
};

export default nextConfig;
