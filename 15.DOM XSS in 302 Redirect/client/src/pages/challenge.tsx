import { ChallengeHeader } from "@/components/challenge-header";
import { ChallengeDescription } from "@/components/challenge-description";
import { ExploitWorkspace } from "@/components/exploit-workspace";
import { BotStatusPanel } from "@/components/bot-status";
import { CapturedCookiesPanel } from "@/components/captured-cookies";
import { HintsPanel } from "@/components/hints-panel";
import { FlagValidation } from "@/components/flag-validation";

export default function ChallengePage() {
  return (
    <div className="min-h-screen bg-background">
      <ChallengeHeader />
      
      <div className="container mx-auto px-6 py-8">
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          <div className="lg:col-span-1 space-y-6">
            <ChallengeDescription />
            <HintsPanel />
          </div>
          
          <div className="lg:col-span-2 space-y-6">
            <ExploitWorkspace />
            
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              <BotStatusPanel />
              <CapturedCookiesPanel />
            </div>
            
            <FlagValidation />
          </div>
        </div>
      </div>
    </div>
  );
}
