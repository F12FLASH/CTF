import { Switch, Route } from "wouter";
import { queryClient } from "./lib/queryClient";
import { QueryClientProvider } from "@tanstack/react-query";
import { Toaster } from "@/components/ui/toaster";
import { TooltipProvider } from "@/components/ui/tooltip";
import { SidebarProvider, SidebarTrigger } from "@/components/ui/sidebar";
import { AppSidebar, LanguageContext } from "@/components/app-sidebar";
import { ThemeToggle } from "@/components/theme-toggle";
import ExploitBuilder from "@/pages/exploit-builder";
import PayloadGenerator from "@/pages/payload-generator";
import Gadgets from "@/pages/gadgets";
import Templates from "@/pages/templates";
import History from "@/pages/history";
import Instructions from "@/pages/instructions";
import SubmitFlag from "@/pages/submit-flag";
import NotFound from "@/pages/not-found";
import { useState, useEffect } from "react";

function Router() {
  return (
    <Switch>
      <Route path="/" component={ExploitBuilder} />
      <Route path="/instructions" component={Instructions} />
      <Route path="/submit" component={SubmitFlag} />
      <Route path="/payload" component={PayloadGenerator} />
      <Route path="/gadgets" component={Gadgets} />
      <Route path="/templates" component={Templates} />
      <Route path="/history" component={History} />
      <Route component={NotFound} />
    </Switch>
  );
}

export default function App() {
  const [lang, setLang] = useState<"en" | "vi">("en");

  useEffect(() => {
    const stored = localStorage.getItem("lang") as "en" | "vi" | null;
    if (stored) {
      setLang(stored);
    }
  }, []);

  const handleSetLang = (newLang: "en" | "vi") => {
    setLang(newLang);
    localStorage.setItem("lang", newLang);
  };

  const style = {
    "--sidebar-width": "16rem",
    "--sidebar-width-icon": "3rem",
  };

  return (
    <QueryClientProvider client={queryClient}>
      <TooltipProvider>
        <LanguageContext.Provider value={{ lang, setLang: handleSetLang }}>
          <SidebarProvider style={style as React.CSSProperties}>
            <div className="flex h-screen w-full">
              <AppSidebar />
              <div className="flex flex-col flex-1 min-w-0">
                <header className="flex items-center justify-between p-2 border-b min-h-9 shrink-0">
                  <SidebarTrigger data-testid="button-sidebar-toggle" />
                  <ThemeToggle />
                </header>
                <main className="flex-1 min-h-0 overflow-hidden">
                  <Router />
                </main>
              </div>
            </div>
          </SidebarProvider>
          <Toaster />
        </LanguageContext.Provider>
      </TooltipProvider>
    </QueryClientProvider>
  );
}
