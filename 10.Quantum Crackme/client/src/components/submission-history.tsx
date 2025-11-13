import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { CheckCircle2, XCircle, Clock } from "lucide-react";
import { useQuery } from "@tanstack/react-query";
import type { Submission } from "@shared/schema";

export function SubmissionHistory() {
  const { data: submissions, isLoading } = useQuery<Submission[]>({
    queryKey: ["/api/submissions"],
  });

  const maskFlag = (flag: string) => {
    if (flag.length <= 20) {
      return flag.substring(0, 8) + "..." + flag.substring(flag.length - 4);
    }
    return flag.substring(0, 15) + "..." + flag.substring(flag.length - 8);
  };

  const formatDate = (date: Date | string) => {
    const d = new Date(date);
    return d.toLocaleString("vi-VN", {
      year: "numeric",
      month: "2-digit",
      day: "2-digit",
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
    });
  };

  if (isLoading) {
    return (
      <section className="py-16 lg:py-24 bg-muted/30">
        <div className="max-w-6xl mx-auto px-6">
          <Card>
            <CardContent className="p-12 text-center">
              <Clock className="w-8 h-8 animate-spin mx-auto mb-4 text-muted-foreground" />
              <p className="text-muted-foreground">Loading submission history...</p>
            </CardContent>
          </Card>
        </div>
      </section>
    );
  }

  if (!submissions || submissions.length === 0) {
    return (
      <section className="py-16 lg:py-24 bg-muted/30">
        <div className="max-w-6xl mx-auto px-6">
          <h2 className="text-3xl lg:text-4xl font-bold mb-12 font-display text-center">
            Lịch Sử <span className="text-primary">Submissions</span>
          </h2>
          <Card>
            <CardContent className="p-12 text-center">
              <p className="text-muted-foreground">Chưa có submission nào. Hãy là người đầu tiên!</p>
            </CardContent>
          </Card>
        </div>
      </section>
    );
  }

  return (
    <section className="py-16 lg:py-24 bg-muted/30">
      <div className="max-w-6xl mx-auto px-6">
        <h2 className="text-3xl lg:text-4xl font-bold mb-12 font-display text-center">
          Lịch Sử <span className="text-primary">Submissions</span>
        </h2>

        <Card className="border-primary/10" data-testid="card-submission-history">
          <CardHeader className="border-b border-border">
            <CardTitle className="font-display flex items-center gap-2">
              <Clock className="w-5 h-5 text-primary" />
              Recent Attempts
            </CardTitle>
          </CardHeader>
          <CardContent className="p-0">
            <div className="overflow-x-auto">
              <Table>
                <TableHeader>
                  <TableRow className="hover:bg-transparent">
                    <TableHead className="font-mono uppercase text-xs">Timestamp</TableHead>
                    <TableHead className="font-mono uppercase text-xs">Attempted Flag</TableHead>
                    <TableHead className="font-mono uppercase text-xs text-right">Status</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {submissions.slice(0, 10).map((submission, idx) => (
                    <TableRow 
                      key={submission.id} 
                      className={idx % 2 === 0 ? "bg-muted/20" : ""}
                      data-testid={`row-submission-${idx}`}
                    >
                      <TableCell className="font-mono text-xs text-muted-foreground">
                        {formatDate(submission.submittedAt)}
                      </TableCell>
                      <TableCell className="font-mono text-sm">
                        {maskFlag(submission.attemptedFlag)}
                      </TableCell>
                      <TableCell className="text-right">
                        {submission.isCorrect ? (
                          <Badge className="gap-1 bg-primary hover:bg-primary" data-testid={`badge-success-${idx}`}>
                            <CheckCircle2 className="w-3 h-3" />
                            Success
                          </Badge>
                        ) : (
                          <Badge variant="destructive" className="gap-1" data-testid={`badge-failed-${idx}`}>
                            <XCircle className="w-3 h-3" />
                            Failed
                          </Badge>
                        )}
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
          </CardContent>
        </Card>
      </div>
    </section>
  );
}
