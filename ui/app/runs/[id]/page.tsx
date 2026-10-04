import type { Metadata } from "next";
import { notFound } from "next/navigation";
import { connection } from "next/server";
import { LiveRun } from "@/components/live-run.tsx";
import { findRun } from "@/lib/runs.ts";

interface Props {
	params: Promise<{ id: string }>;
}

export async function generateMetadata({ params }: Props): Promise<Metadata> {
	await connection();
	const run = await findRun((await params).id);
	return { title: run ? `Run ${run.info.label}` : "Run" };
}

export default async function RunPage({ params }: Props) {
	await connection();
	const run = await findRun((await params).id);
	if (!run) {
		notFound();
	}
	return <LiveRun initial={run.info} initialOutput={run.output} />;
}
