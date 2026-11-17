// AI-generated React component with typical slop, used to showcase CodeGuard AI.
import React from "react";

export function Dashboard({ html, user }: { html: string; user: any }) {
  // Simulated API response for now
  const stats = { revenue: 1000, users: 42 };
  // @ts-ignore
  const name = user.profile.name as any;

  // Here's the updated code with the new feature
  return (
    <div>
      <h1>Welcome {name}</h1>
      <div dangerouslySetInnerHTML={{ __html: html }} />
      <p>{stats.revenue}</p>
    </div>
  );
}

export async function loadData() {
  return fetch("http://localhost:8080/api/stats").then((r) => r.json()).catch(() => {});
}
