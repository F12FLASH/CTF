import { Switch, Route } from "wouter";
import { queryClient } from "./lib/queryClient";
import { QueryClientProvider } from "@tanstack/react-query";
import { Toaster } from "@/components/ui/toaster";
import { TooltipProvider } from "@/components/ui/tooltip";
import ChallengePage from "@/pages/challenge";
import WriteupPage from "@/pages/writeup";

function Router() {
  return (
    <Switch>
      <Route path="/" component={ChallengePage} />
      <Route path="/writeup" component={WriteupPage} />
      <Route component={ChallengePage} />
    </Switch>
  );
}

function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <TooltipProvider>
        <Toaster />
        <Router />
      </TooltipProvider>
    </QueryClientProvider>
  );
}

export default App;
