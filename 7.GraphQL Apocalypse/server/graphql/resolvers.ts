import { storage } from "../storage";
import { encodeFlag, getFlagHint } from "../crypto/flagEncoder";

export const resolvers = {
  Query: {
    hello: () => {
      return "Chào mừng đến với GraphQL Apocalypse. Sử dụng introspection để khám phá bí mật ẩn.";
    },

    users: async () => {
      return await storage.getUsers();
    },

    flag: async () => {
      return await storage.getFlag();
    },

    serverInfo: () => {
      return {
        version: "1.0.0-apocalypse",
        endpoint: "/api/graphql",
        introspectionEnabled: true,
      };
    },
  },

  Mutation: {
    ping: (_: unknown, args: { message: string }) => {
      return `Pong: ${args.message}`;
    },

    unlockSecretVault: async (_: unknown, args: { accessKey: any }) => {
      const { accessKey } = args;
      
      let accessCode: string | null = null;

      if (typeof accessKey === 'string') {
        accessCode = accessKey;
      } else if (accessKey && typeof accessKey === 'object') {
        if (accessKey.code) {
          accessCode = accessKey.code;
        } else if (accessKey.value !== undefined) {
          accessCode = String(accessKey.value);
        } else if (accessKey.data) {
          try {
            const parsed = JSON.parse(accessKey.data);
            if (parsed.secret) {
              accessCode = parsed.secret;
            }
          } catch {
            accessCode = accessKey.data;
          }
        }
      } else if (typeof accessKey === 'number') {
        accessCode = String(accessKey);
      }

      if (!accessCode) {
        return null;
      }

      const result = await storage.unlockSecretData(accessCode);
      
      if (result) {
        const encodedFlag = encodeFlag(result.flag);
        return {
          flag: encodedFlag,
          message: "Quyền truy cập được cấp! Bạn đã khai thác thành công lỗ hổng type confusion. " + getFlagHint(),
        };
      }

      return null;
    },
  },
};
