'use client';
import React, { useState } from 'react';
import Link from 'next/link';

export default function LoginPage() {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    const result = await fetch('http://192.168.122.109:5000/api/login', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ username: email, password }),
    });

    if (result.ok) {
      const data = await result.json();
      console.log('Login successful:', data);
    } else {
      console.error('Login failed');
    }
  };

  return (
    <div className="min-h-dvh w-full flex items-center justify-center bg-gray-100 px-4">
      <div className="w-full max-w-md bg-white p-8 rounded-xl shadow-lg">

        <div className="text-center mb-8">
          <h1 className="text-2xl font-bold text-gray-800">ยินดีต้อนรับกลับ</h1>
          <p className="text-gray-500 text-sm mt-2">กรุณาเข้าสู่ระบบเพื่อใช้งานต่อ</p>
        </div>

        <form onSubmit={handleSubmit} className="space-y-6">
          <div>
            <label htmlFor="email" className="block text-sm font-medium text-gray-700 mb-1">
              อีเมล
            </label>
            <input
              type="email"
              id="email"
              className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-blue-500 outline-none transition-all"
              placeholder="name@company.com"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              required
            />
          </div>

          <div>
            <div className="flex items-center justify-between mb-1">
              <label htmlFor="password" className="block text-sm font-medium text-gray-700">
                รหัสผ่าน
              </label>
              {/* ใช้ Link แทน a tag */}
              <Link href="/forgot-password" className="text-sm text-blue-600 hover:underline">
                ลืมรหัสผ่าน?
              </Link>
            </div>
            <input
              type="password"
              id="password"
              className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-blue-500 outline-none transition-all"
              placeholder="••••••••"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              required
            />
          </div>

          <button
            type="submit"
            className="w-full bg-blue-600 hover:bg-blue-700 text-white font-medium py-2.5 rounded-lg transition-colors duration-200"
          >
            เข้าสู่ระบบ
          </button>
        </form>

        <p className="mt-6 text-center text-sm text-gray-600">
          ยังไม่มีบัญชีใช่ไหม?{' '}
          {/* ใช้ Link แทน a tag */}
          <Link href="/register" className="text-blue-600 font-medium hover:underline">
            สมัครสมาชิก
          </Link>
        </p>
      </div>
    </div>
  );
}