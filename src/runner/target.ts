import { spawn, type ChildProcess } from "node:child_process";
import { resolve } from "node:path";
import type { TargetConfig } from "./config.ts";

/**
 * Starts an implementation under test (`target` in the config) and waits until its ready URL answers.
 * If the ready URL already answers before starting, the target is assumed to be running externally and is left alone.
 */
export class Target {
	private child: ChildProcess | null = null;
	private readonly cfg: TargetConfig;
	private readonly root: string;
	readonly output: string[] = [];
	private startedByUs = false;

	constructor(cfg: TargetConfig, root = process.cwd()) {
		this.cfg = cfg;
		this.root = root;
	}

	async start(): Promise<void> {
		if (await this.isReady()) {
			return;
		}
		const [cmd, ...cmdArgs] = this.cfg.command.split(/\s+/);
		this.child = spawn(cmd, cmdArgs, {
			cwd: this.cfg.cwd ? resolve(this.root, this.cfg.cwd) : this.root,
			env: { ...process.env, ...(this.cfg.env ?? {}) },
			stdio: ["ignore", "pipe", "pipe"],
		});
		this.startedByUs = true;
		const capture = (chunk: Buffer) => {
			const text = chunk.toString();
			this.output.push(text);
			if (this.output.length > 2000) {
				this.output.splice(0, this.output.length - 2000);
			}
			if (process.env["CONFORMANCE_TARGET_OUTPUT"]) {
				process.stderr.write(`[target] ${text}`);
			}
		};
		this.child.stdout?.on("data", capture);
		this.child.stderr?.on("data", capture);
		const exited = new Promise<never>((_, reject) => {
			this.child?.once("exit", (code) =>
				reject(new Error(`target '${this.cfg.command}' exited with code ${code}\n${this.output.join("")}`)),
			);
		});
		const deadline = Date.now() + (this.cfg.timeoutSeconds ?? 60) * 1000;
		while (Date.now() < deadline) {
			if (await Promise.race([this.isReady(), exited])) {
				return;
			}
			await new Promise((r) => setTimeout(r, 250));
		}
		await this.stop();
		throw new Error(
			`target '${this.cfg.command}' did not become ready at ${this.cfg.readyUrl}\n${this.output.join("")}`,
		);
	}

	private async isReady(): Promise<boolean> {
		try {
			const res = await fetch(this.cfg.readyUrl, { signal: AbortSignal.timeout(2000) });
			return res.status < 500;
		} catch {
			return false;
		}
	}

	async stop(): Promise<void> {
		if (!this.child || !this.startedByUs) {
			return;
		}
		const child = this.child;
		this.child = null;
		if (child.exitCode !== null) {
			return;
		}
		await new Promise<void>((resolveStop) => {
			child.once("exit", () => resolveStop());
			child.kill("SIGTERM");
			setTimeout(() => {
				if (child.exitCode === null) {
					child.kill("SIGKILL");
				}
			}, 3000).unref();
		});
	}
}
