import { useState } from "react";
import { Hero } from "@/components/hero";
import { QueryEditor } from "@/components/query-editor";
import { ChallengeInfo } from "@/components/challenge-info";
import { FlagModal } from "@/components/flag-modal";
import { Header } from "@/components/header";
import { IntrospectionExplorer } from "@/components/introspection-explorer";

export default function Home() {
  const [isIntrospectionOpen, setIsIntrospectionOpen] = useState(false);
  const [isFlagModalOpen, setIsFlagModalOpen] = useState(false);

  return (
    <div className="min-h-screen bg-background text-foreground">
      <Header onOpenFlagModal={() => setIsFlagModalOpen(true)} />
      
      <Hero />
      
      <main className="relative">
        <div className="flex">
          <IntrospectionExplorer 
            isOpen={isIntrospectionOpen} 
            onToggle={() => setIsIntrospectionOpen(!isIntrospectionOpen)} 
          />
          
          <div className={`flex-1 transition-all duration-300 ${isIntrospectionOpen ? 'ml-80' : 'ml-0'}`}>
            <QueryEditor />
          </div>
        </div>
        
        <ChallengeInfo />
      </main>
      
      <FlagModal 
        isOpen={isFlagModalOpen} 
        onClose={() => setIsFlagModalOpen(false)} 
      />
    </div>
  );
}
