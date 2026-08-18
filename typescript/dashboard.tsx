'use client';
import { useEffect, useState } from 'react';

export default function Dashboard() {
  const [data, setData] = useState(null);
  useEffect(() => {
    fetch('/api/dashboard').then(r => r.json()).then(setData);
  }, []);
  return <div>{JSON.stringify(data)}</div>;
}
