import { Suspense } from "react";

import { UsersClientPage } from "./UsersClientPage";

export default function UsersPage() {
  return (
    <Suspense fallback={<main className="mx-auto min-h-screen w-full max-w-6xl px-6 py-8">Loading users...</main>}>
      <UsersClientPage />
    </Suspense>
  );
}
