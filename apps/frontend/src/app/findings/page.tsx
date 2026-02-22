import { Suspense } from "react";

import { FindingsClientPage } from "./FindingsClientPage";

export default function FindingsPage() {
  return (
    <Suspense fallback={<main className="mx-auto min-h-screen w-full max-w-6xl px-6 py-8">Loading findings...</main>}>
      <FindingsClientPage />
    </Suspense>
  );
}
