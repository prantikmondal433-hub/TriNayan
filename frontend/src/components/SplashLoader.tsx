"use client";

import Image from "next/image";

interface SplashLoaderProps {
  message?: string;
  subMessage?: string;
  isFadingOut?: boolean;
}

export function SplashLoader({
  message = "TriNayan",
  subMessage = "Passive Security Analysis · Initializing...",
  isFadingOut = false,
}: SplashLoaderProps) {
  return (
    <div
      role="status"
      aria-live="polite"
      className={`fixed inset-0 z-50 bg-[var(--tn-bg)] flex flex-col items-center justify-center px-4 transition-opacity duration-400 ease-out ${
        isFadingOut ? "opacity-0 pointer-events-none" : "opacity-100"
      }`}
    >
      {/* Background ambient radial glow */}
      <div
        aria-hidden="true"
        className="absolute w-72 h-72 sm:w-96 sm:h-96 rounded-full bg-blue-600/15 blur-3xl pointer-events-none animate-pulse-halo"
      />

      {/* Slowly beating Shield Logo */}
      <div className="relative z-10 flex flex-col items-center">
        <div className="relative w-32 h-36 sm:w-40 sm:h-44 mb-6">
          <Image
            src="/logo.png"
            alt="TriNayan Security Shield Logo"
            fill
            priority
            sizes="(max-width: 640px) 128px, 160px"
            className="object-contain animate-slow-beat"
          />
        </div>

        <h1 className="text-2xl sm:text-3xl font-extrabold text-[var(--tn-text)] tracking-tight mb-2">
          {message}
        </h1>
        <p className="text-xs sm:text-sm text-[var(--tn-text-secondary)] font-medium tracking-wide text-center">
          {subMessage}
        </p>

        {/* Breathing dots */}
        <div aria-hidden="true" className="flex items-center gap-1.5 mt-5">
          <span className="w-1.5 h-1.5 rounded-full bg-blue-400 animate-pulse" />
          <span className="w-1.5 h-1.5 rounded-full bg-blue-400 animate-pulse [animation-delay:200ms]" />
          <span className="w-1.5 h-1.5 rounded-full bg-blue-400 animate-pulse [animation-delay:400ms]" />
        </div>
      </div>
      <span className="sr-only">Loading security analyzer</span>
    </div>
  );
}
