"use client";

import React, { useState, useRef } from "react";

const Page: React.FC = () => {
  const [payload, setPayload] = useState<string>("");
  const containerRef = useRef<HTMLDivElement>(null);

  // ฟังก์ชันนี้จะ "บังคับ" ให้ Browser รันโค้ด HTML/JS ที่คุณพิมพ์
  const executePayload = () => {
    const container = containerRef.current;
    if (!container) return;

    // 1. ล้างเนื้อหาเก่าออกก่อน
    container.innerHTML = "";

    // 2. เทคนิค bypass React security:
    // การใช้ innerHTML ธรรมดาใน React จะไม่รัน <script>
    // เราจึงต้องใช้ createContextualFragment เพื่อให้ Browser มองว่าเป็นโค้ดใหม่ที่ต้อง Execute
    try {
      const range = document.createRange();
      range.selectNode(container); // บอกขอบเขตว่าจะวางตรงไหน
      const fragment = range.createContextualFragment(payload); // แปลง String เป็น DOM ที่รันได้

      container.appendChild(fragment); // ยัดลงหน้าเว็บ -> บู้ม! รันทันที
    } catch (err) {
      console.error("Invalid HTML/JS:", err);
    }
  };

  return (
    <div className="min-h-screen bg-black text-green-500 font-mono p-8 flex flex-col items-center">
      <h1 className="text-3xl font-bold mb-6 text-red-500 border-b border-red-500 pb-2">
        💀 Local XSS Executor
      </h1>

      <div className="w-full max-w-2xl">
        <label className="block mb-2 text-sm opacity-80">
          พิมพ์ Payload ที่นี่ (กด Execute เพื่อรันบน Browser นี้เลย):
        </label>

        <textarea
          className="w-full h-40 bg-gray-900 border border-green-700 p-4 rounded focus:outline-none focus:border-red-500 text-white"
          placeholder="<script>alert('Test')</script>"
          value={payload}
          onChange={(e) => setPayload(e.target.value)}
        />

        <button
          onClick={executePayload}
          className="mt-4 w-full bg-red-600 hover:bg-red-700 text-white font-bold py-3 px-6 rounded transition"
        >
          EXECUTE PAYLOAD 💥
        </button>
      </div>

      {/* พื้นที่ประหาร: โค้ดจะมารันตรงนี้ */}
      <div className="mt-10 w-full max-w-2xl">
        <p className="text-gray-500 text-sm mb-2">👇 Result Zone (DOM Injection Point)</p>
        <div
          ref={containerRef}
          className="border-2 border-dashed border-gray-700 p-6 min-h-[100px] rounded bg-gray-900"
        >
          {/* script จะทำงานตรงนี้ */}
        </div>
      </div>
    </div>
  );
};

export default Page;