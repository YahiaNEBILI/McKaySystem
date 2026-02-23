import { Suspense } from "react";

import { RecommendationsClientPage } from "./RecommendationsClientPage";

const loadingFallback = (
  <main className="finops-shell relative overflow-hidden">
    <div className="finops-orb finops-orb--one" />
    <div className="finops-orb finops-orb--two" />
    <div className="finops-orb finops-orb--three" />
    <div className="relative z-10 mx-auto min-h-screen w-full max-w-7xl px-6 py-6">
      <section className="finops-panel rounded-2xl p-6 text-sm text-slate-700">
        Loading recommendations...
      </section>
    </div>
  </main>
);

export default function RecommendationsPage() {
  return (
    <Suspense fallback={loadingFallback}>
      <RecommendationsClientPage />
    </Suspense>
  );
}
