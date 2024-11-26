#include <gtest/gtest.h>
#include "include/buffer.h"

namespace server {
namespace {

class BufferTest : public ::testing::Test {
protected:
    Buffer buffer_;  // 使用默認大小初始化
};

// 測試初始化狀態
TEST_F(BufferTest, InitialState) {
    EXPECT_EQ(buffer_.readableBytes(), 0);
    EXPECT_EQ(buffer_.writableBytes(), Buffer::DEFAULT_INIT_SIZE);
    EXPECT_EQ(buffer_.prependableBytes(), Buffer::PREPEND_SIZE);
}

// 測試基本的寫入和讀取
TEST_F(BufferTest, AppendAndRetrieve) {
    std::string test_str = "Hello, World!";
    buffer_.append(test_str);
    
    EXPECT_EQ(buffer_.readableBytes(), test_str.length());
    EXPECT_EQ(buffer_.retrieveAsString(test_str.length()), test_str);
    EXPECT_EQ(buffer_.readableBytes(), 0);
}

// 測試多次寫入和完整讀取
TEST_F(BufferTest, MultipleAppendAndRetrieveAll) {
    std::string str1 = "Hello";
    std::string str2 = " World";
    buffer_.append(str1);
    buffer_.append(str2);
    
    EXPECT_EQ(buffer_.readableBytes(), str1.length() + str2.length());
    EXPECT_EQ(buffer_.retrieveAllAsString(), str1 + str2);
    EXPECT_EQ(buffer_.readableBytes(), 0);
}

// 測試緩衝區擴展
TEST_F(BufferTest, EnsureSpace) {
    std::string large_str(Buffer::DEFAULT_INIT_SIZE * 2, 'x');
    buffer_.append(large_str);
    
    EXPECT_EQ(buffer_.readableBytes(), large_str.length());
    EXPECT_EQ(buffer_.retrieveAllAsString(), large_str);
}

// 測試部分讀取
TEST_F(BufferTest, PartialRetrieve) {
    std::string test_str = "Hello, World!";
    buffer_.append(test_str);
    
    std::string part = buffer_.retrieveAsString(5);  // 讀取 "Hello"
    EXPECT_EQ(part, "Hello");
    EXPECT_EQ(buffer_.readableBytes(), test_str.length() - 5);
    EXPECT_EQ(buffer_.retrieveAllAsString(), ", World!");
}

// 測試清空緩衝區
TEST_F(BufferTest, RetrieveAll) {
    buffer_.append("Hello");
    buffer_.retrieveAll();
    
    EXPECT_EQ(buffer_.readableBytes(), 0);
    EXPECT_EQ(buffer_.prependableBytes(), Buffer::PREPEND_SIZE);
}

// 測試異常情況
TEST_F(BufferTest, RetrieveMoreThanAvailable) {
    buffer_.append("Hello");
    EXPECT_THROW(buffer_.retrieveAsString(10), std::out_of_range);
}

// 測試空字符串操作
TEST_F(BufferTest, EmptyStringOperations) {
    buffer_.append("");
    EXPECT_EQ(buffer_.readableBytes(), 0);
    EXPECT_EQ(buffer_.retrieveAllAsString(), "");
}

// 測試大量數據寫入和讀取
TEST_F(BufferTest, LargeDataOperations) {
    // 創建一個較大的數據串
    const size_t large_size = Buffer::DEFAULT_INIT_SIZE * 4;
    std::string large_data(large_size, 'A');
    
    buffer_.append(large_data);
    EXPECT_EQ(buffer_.readableBytes(), large_size);
    EXPECT_EQ(buffer_.retrieveAllAsString(), large_data);
}

// 測試連續的寫入讀取操作
TEST_F(BufferTest, ContinuousWriteAndRead) {
    for (int i = 0; i < 100; ++i) {
        std::string data = "test" + std::to_string(i);
        buffer_.append(data);
        EXPECT_EQ(buffer_.retrieveAsString(data.length()), data);
    }
    EXPECT_EQ(buffer_.readableBytes(), 0);
}

}  // namespace
}  // namespace server

// 主函數運行所有測試
int main(int argc, char **argv) {
    testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
