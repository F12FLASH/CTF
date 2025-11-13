import type { Express } from "express";
import { createServer, type Server } from "http";
import { graphqlHTTP } from "express-graphql";
import { makeExecutableSchema } from "@graphql-tools/schema";
import validator from "validator";
import { typeDefs } from "./graphql/schema";
import { resolvers } from "./graphql/resolvers";
import { storage } from "./storage";
import { flagVault } from "./crypto/flagVault";
import { GraphQLError } from "graphql";

const schema = makeExecutableSchema({
  typeDefs,
  resolvers,
});

const _0x7f3a = (s: string) => Buffer.from(s, 'base64').toString('utf-8');
const _0x8e2b = (a: number[], k: number) => String.fromCharCode(...a.map(c => c ^ k));

const clientAttempts = new Map<string, { count: number; lastAttempt: number }>();

function getClientIdentifier(req: any): string {
  return req.ip || req.connection?.remoteAddress || 'unknown';
}

function calculateQueryDepth(query: string): number {
  let depth = 0;
  let currentDepth = 0;
  let inString = false;
  
  for (let i = 0; i < query.length; i++) {
    const char = query[i];
    
    if (char === '"' && query[i - 1] !== '\\') {
      inString = !inString;
    }
    
    if (!inString) {
      if (char === '{') {
        currentDepth++;
        if (currentDepth > depth) {
          depth = currentDepth;
        }
      } else if (char === '}') {
        currentDepth--;
      }
    }
  }
  
  return depth;
}

export async function registerRoutes(app: Express): Promise<Server> {
  app.use(
    "/api/graphql",
    (req, res, next) => {
      try {
        const clientId = getClientIdentifier(req);
        const now = Date.now();
        
        const clientData = clientAttempts.get(clientId);
        if (clientData) {
          if (now - clientData.lastAttempt < 1000 && clientData.count > 10) {
            return res.status(429).json({
              errors: [{
                message: 'Too many requests. Please slow down.',
              }]
            });
          }
          
          if (now - clientData.lastAttempt > 60000) {
            clientAttempts.delete(clientId);
          }
        }
        
        const query = req.body?.query || (req.query?.query as string);
        
        if (query) {
          const depth = calculateQueryDepth(query);
          if (depth > 15) {
            return res.status(400).json({
              errors: [{
                message: 'Query too complex. Maximum depth exceeded.',
              }]
            });
          }
          
          const attempts = clientAttempts.get(clientId) || { count: 0, lastAttempt: 0 };
          attempts.count++;
          attempts.lastAttempt = now;
          clientAttempts.set(clientId, attempts);
        }
        
        next();
      } catch (error) {
        next(error);
      }
    },
    graphqlHTTP({
      schema,
      graphiql: false,
      customFormatErrorFn: (error) => {
        const message = error.message;
        if (message && (message.includes('VNFLAG') || message.includes('FLAG{'))) {
          return {
            message: 'An error occurred processing your request',
            locations: error.locations,
            path: error.path,
          };
        }
        return {
          message: error.message,
          locations: error.locations,
          path: error.path,
        };
      },
    })
  );

  app.post("/api/submit-flag", async (req, res) => {
    try {
      const { flag } = req.body;

      if (!flag || typeof flag !== "string") {
        return res.status(400).json({
          success: false,
          message: "Định dạng flag không hợp lệ",
        });
      }

      const sanitizedFlag = validator.trim(flag);
      
      if (sanitizedFlag.length === 0 || sanitizedFlag.length > 200) {
        return res.status(400).json({
          success: false,
          message: "Flag phải có độ dài từ 1-200 ký tự",
        });
      }

      const _expectedFlag = flagVault.getFlag();

      if (sanitizedFlag === _expectedFlag) {
        return res.json({
          success: true,
          message: "Chúc mừng! Bạn đã hoàn thành thử thách GraphQL Apocalypse!",
        });
      } else {
        return res.json({
          success: false,
          message: "Flag không chính xác. Hãy tiếp tục khám phá GraphQL schema và tìm kiếm lỗ hổng type confusion.",
        });
      }
    } catch (error) {
      console.error('Error in submit-flag:', error);
      return res.status(500).json({
        success: false,
        message: "Đã xảy ra lỗi khi xử lý flag",
      });
    }
  });

  const httpServer = createServer(app);

  return httpServer;
}
