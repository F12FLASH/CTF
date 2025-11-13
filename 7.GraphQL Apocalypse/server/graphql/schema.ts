export const typeDefs = `
  type Query {
    hello: String!
    users: [User!]!
    flag: String!
    serverInfo: ServerInfo!
  }

  type Mutation {
    ping(message: String!): String!
    """
    Mutation ẩn - yêu cầu mã truy cập đặc biệt
    Gợi ý: Lỗ hổng này có tên tiếng Anh ghép từ TYPE + tên vấn đề + EXPLOIT
    Hãy nghiên cứu kỹ loại lỗ hổng được mô tả trong AccessKey input type
    """
    unlockSecretVault(accessKey: AccessKey!): SecretData
  }

  type User {
    id: ID!
    username: String!
  }

  type ServerInfo {
    version: String!
    endpoint: String!
    introspectionEnabled: Boolean!
  }

  type SecretData {
    flag: String!
    message: String!
  }

  """
  Access key input type - chấp nhận nhiều định dạng khác nhau
  Lỗ hổng: TYPE CONFUSION - String vs Int vs Object
  Access code format: [TÊN_LỖ_HỔNG]_[EXPLOIT] (viết hoa, dấu gạch dưới)
  """
  input AccessKey {
    code: String
    value: Int
    data: String
  }
`;
