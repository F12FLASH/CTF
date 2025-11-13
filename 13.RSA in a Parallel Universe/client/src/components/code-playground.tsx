import { useState } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Code, Play } from "lucide-react";
import Editor from "react-simple-code-editor";
import Prism from "prismjs";
import "prismjs/components/prism-python";
import "prismjs/themes/prism-tomorrow.css";

const PYTHON_TEMPLATE = `def gaussian_gcd(a, b):
    """GCD for Gaussian integers"""
    while b != 0:
        a, b = b, a - b * (a // b)
    return a

def norm(z):
    """Norm of Gaussian integer"""
    return z.real**2 + z.imag**2

# Test your code here
z = complex(3, 4)
print(f"Norm of {z}: {norm(z)}")`;

const JAVASCRIPT_TEMPLATE = `function gaussianNorm(real, imag) {
  // Norm of Gaussian integer
  return real * real + imag * imag;
}

function gaussianMultiply(a, b) {
  // Multiply two Gaussian integers
  return {
    real: a.real * b.real - a.imag * b.imag,
    imag: a.real * b.imag + a.imag * b.real
  };
}

// Test your code here
const z = { real: 3, imag: 4 };
console.log(\`Norm: \${gaussianNorm(z.real, z.imag)}\`);`;

export function CodePlayground() {
  const [pythonCode, setPythonCode] = useState(PYTHON_TEMPLATE);
  const [jsCode, setJsCode] = useState(JAVASCRIPT_TEMPLATE);
  const [output, setOutput] = useState("");
  const [activeTab, setActiveTab] = useState("python");

  const runCode = () => {
    if (activeTab === "python") {
      setOutput("Python execution requires a backend service.\nCode saved for reference.");
    } else {
      try {
        const logs: string[] = [];
        const originalLog = console.log;
        console.log = (...args) => {
          logs.push(args.join(" "));
        };
        
        eval(jsCode);
        
        console.log = originalLog;
        setOutput(logs.join("\n") || "Code executed successfully (no output)");
      } catch (error) {
        setOutput(`Error: ${error instanceof Error ? error.message : String(error)}`);
      }
    }
  };

  return (
    <Card className="border rounded-lg" data-testid="card-code-playground">
      <CardHeader className="p-6">
        <div className="flex items-center gap-3">
          <Code className="w-6 h-6 text-primary" />
          <CardTitle className="text-xl">Code Playground</CardTitle>
        </div>
        <p className="text-sm text-muted-foreground mt-2">
          Test your Gaussian integer implementations
        </p>
      </CardHeader>
      <CardContent className="p-6 pt-0">
        <Tabs value={activeTab} onValueChange={setActiveTab}>
          <TabsList className="mb-4">
            <TabsTrigger value="python" data-testid="tab-python">
              Python
            </TabsTrigger>
            <TabsTrigger value="javascript" data-testid="tab-javascript">
              JavaScript
            </TabsTrigger>
          </TabsList>

          <TabsContent value="python" className="mt-0">
            <div className="border rounded-md overflow-hidden">
              <div className="h-10 flex items-center justify-between px-4 border-b bg-muted/30">
                <span className="text-sm font-medium">editor.py</span>
                <Button
                  size="sm"
                  onClick={runCode}
                  data-testid="button-run-python"
                >
                  <Play className="w-4 h-4 mr-2" />
                  Run
                </Button>
              </div>
              <div className="bg-[#2d2d2d] p-4 overflow-auto max-h-96">
                <Editor
                  value={pythonCode}
                  onValueChange={setPythonCode}
                  highlight={(code) => Prism.highlight(code, Prism.languages.python, 'python')}
                  padding={0}
                  className="font-mono text-sm"
                  style={{
                    fontFamily: 'JetBrains Mono, monospace',
                    fontSize: '14px',
                    minHeight: '200px',
                  }}
                  data-testid="editor-python"
                />
              </div>
            </div>
          </TabsContent>

          <TabsContent value="javascript" className="mt-0">
            <div className="border rounded-md overflow-hidden">
              <div className="h-10 flex items-center justify-between px-4 border-b bg-muted/30">
                <span className="text-sm font-medium">script.js</span>
                <Button
                  size="sm"
                  onClick={runCode}
                  data-testid="button-run-javascript"
                >
                  <Play className="w-4 h-4 mr-2" />
                  Run
                </Button>
              </div>
              <div className="bg-[#2d2d2d] p-4 overflow-auto max-h-96">
                <Editor
                  value={jsCode}
                  onValueChange={setJsCode}
                  highlight={(code) => Prism.highlight(code, Prism.languages.javascript, 'javascript')}
                  padding={0}
                  className="font-mono text-sm"
                  style={{
                    fontFamily: 'JetBrains Mono, monospace',
                    fontSize: '14px',
                    minHeight: '200px',
                  }}
                  data-testid="editor-javascript"
                />
              </div>
            </div>
          </TabsContent>
        </Tabs>

        {output && (
          <div className="mt-4 p-4 border rounded-md bg-card font-mono text-sm" data-testid="output-display">
            <div className="text-xs font-semibold text-muted-foreground mb-2">OUTPUT:</div>
            <pre className="whitespace-pre-wrap">{output}</pre>
          </div>
        )}
      </CardContent>
    </Card>
  );
}
