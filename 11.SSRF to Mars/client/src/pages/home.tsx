import { useState } from "react";
import { ChallengeHero } from "@/components/challenge-hero";
import { ChallengeTabs } from "@/components/challenge-tabs";
import { URLFetcher } from "@/components/url-fetcher";
import { ResponseDisplay } from "@/components/response-display";
import { PayloadGrid } from "@/components/payload-grid";
import { FlagSubmitCard } from "@/components/flag-submit-card";
import type { FetchResponse } from "@shared/schema";

export default function Home() {
  const [currentResponse, setCurrentResponse] = useState<FetchResponse | null>(null);
  const [selectedUrl, setSelectedUrl] = useState("");

  const handlePayloadSelect = (url: string) => {
    setSelectedUrl(url);
    setTimeout(() => {
      document.getElementById('url-fetcher')?.scrollIntoView({ behavior: 'smooth' });
    }, 100);
  };

  return (
    <div className="min-h-screen bg-background">
      <ChallengeHero />

      <div className="container mx-auto px-4 py-12 space-y-12">
        <section>
          <ChallengeTabs />
        </section>

        <section id="url-fetcher" className="scroll-mt-20">
          <h2 className="text-2xl font-bold mb-6" data-testid="text-section-heading-fetcher">Kiểm thử Payload</h2>
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <URLFetcher 
              initialUrl={selectedUrl}
              onResponse={setCurrentResponse}
            />
            <ResponseDisplay response={currentResponse} />
          </div>
        </section>

        <section>
          <PayloadGrid onPayloadSelect={handlePayloadSelect} />
        </section>

        <section>
          <h2 className="text-2xl font-bold mb-6">Hoàn thành Thử thách</h2>
          <div className="max-w-2xl">
            <FlagSubmitCard />
          </div>
        </section>

        <section className="border-t border-border pt-8">
          <div className="bg-card rounded-md p-6 border border-card-border">
            <h3 className="text-lg font-bold mb-3" data-testid="text-skills-heading">Kỹ năng Yêu cầu</h3>
            <div className="flex flex-wrap gap-2">
              {[
                'Lỗ hổng SSRF',
                'Giao thức DNS & HTTP',
                'Bảo mật Mạng',
                'Kỹ thuật Vượt Filter',
                'Kiến thức IPv6',
                'Biểu diễn Địa chỉ IP',
              ].map((skill) => (
                <span
                  key={skill}
                  className="px-3 py-1 bg-primary/10 text-primary rounded-md text-sm font-mono border border-primary/20"
                >
                  {skill}
                </span>
              ))}
            </div>
          </div>
        </section>
      </div>
    </div>
  );
}
