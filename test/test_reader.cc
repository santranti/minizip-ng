/* test_reader.cc - Test zip reader functionality
   part of the minizip-ng project

   Copyright (C) Nathan Moinvaziri
     https://github.com/zlib-ng/minizip-ng

   This program is distributed under the terms of the same license as zlib.
   See the accompanying LICENSE file for the full text of the license.
*/

#include "mz.h"
#include "mz_os.h"
#include "mz_strm.h"
#include "mz_strm_mem.h"
#include "mz_zip.h"
#include "mz_zip_rw.h"
#ifdef HAVE_WZAES
#  include "mz_strm_wzaes.h"
#endif

#include <gtest/gtest.h>

#include <cstdlib>
#include <cstring>
#include <ctime>
#include <string>
#include <vector>

#ifdef HAVE_WZAES
static int32_t read_aes_entry(const std::vector<uint8_t> &archive, std::string *contents, int32_t read_limit = 0) {
    void *reader = mz_zip_reader_create();
    char buffer[64];
    int32_t err = MZ_OK;
    int32_t read = 0;

    if (!reader)
        return MZ_MEM_ERROR;

    err = mz_zip_reader_open_buffer(reader, archive.data(), (int32_t)archive.size(), 1);
    if (err == MZ_OK)
        err = mz_zip_reader_goto_first_entry(reader);
    if (err == MZ_OK) {
        mz_zip_reader_set_password(reader, "password");
        err = mz_zip_reader_entry_open(reader);
    }

    if (err == MZ_OK) {
        do {
            read = mz_zip_reader_entry_read(reader, buffer, read_limit ? read_limit : (int32_t)sizeof(buffer));
            if (read > 0)
                contents->append(buffer, read);
        } while (read > 0 && !read_limit);

        if (read < 0)
            err = read;
        else
            err = mz_zip_reader_entry_close(reader);
    }

    mz_zip_reader_close(reader);
    mz_zip_reader_delete(&reader);
    return err;
}

static int32_t read_aes_entry_with_descriptor(const std::vector<uint8_t> &archive, uint8_t raw = 0,
                                              const char *password = "password") {
    void *mem_stream = mz_stream_mem_create();
    void *zip = mz_zip_create();
    char buffer[64];
    uint32_t crc32 = 0;
    int32_t err = MZ_OK;
    int32_t read = 0;

    if (!mem_stream || !zip) {
        mz_zip_delete(&zip);
        mz_stream_mem_delete(&mem_stream);
        return MZ_MEM_ERROR;
    }

    mz_stream_mem_set_buffer(mem_stream, (void *)archive.data(), (int32_t)archive.size());
    err = mz_stream_mem_open(mem_stream, nullptr, MZ_OPEN_MODE_READ);
    if (err == MZ_OK)
        err = mz_zip_open(zip, mem_stream, MZ_OPEN_MODE_READ);
    if (err == MZ_OK)
        err = mz_zip_goto_first_entry(zip);
    if (err == MZ_OK)
        err = mz_zip_entry_read_open(zip, raw, password);

    if (err == MZ_OK) {
        do {
            read = mz_zip_entry_read(zip, buffer, sizeof(buffer));
        } while (read > 0);

        if (read < 0)
            err = read;
        else
            err = mz_zip_entry_read_close(zip, &crc32, nullptr, nullptr);
    }

    mz_zip_close(zip);
    mz_zip_delete(&zip);
    mz_stream_mem_close(mem_stream);
    mz_stream_mem_delete(&mem_stream);
    return err;
}

TEST(zip_reader_aes, verifies_authentication_on_close) {
    const char plaintext[] = "authenticated contents";
    const void *zip_buffer = nullptr;
    void *mem_stream = mz_stream_mem_create();
    void *zip = mz_zip_create();
    void *reader = mz_zip_reader_create();
    mz_zip_file file_info = {};
    mz_zip_file *read_info = nullptr;
    int64_t zip_buffer_length = 0;
    size_t data_offset = 0;
    size_t tag_offset = 0;
    std::vector<uint8_t> archive;
    std::string contents;

    ASSERT_NE(mem_stream, nullptr);
    ASSERT_NE(zip, nullptr);
    ASSERT_NE(reader, nullptr);
    ASSERT_EQ(mz_stream_mem_open(mem_stream, nullptr, MZ_OPEN_MODE_CREATE), MZ_OK);
    ASSERT_EQ(mz_zip_open(zip, mem_stream, MZ_OPEN_MODE_WRITE), MZ_OK);

    file_info.filename = "contents.txt";
    file_info.version_madeby = MZ_VERSION_MADEBY;
    file_info.compression_method = MZ_COMPRESS_METHOD_STORE;
    file_info.aes_version = 2;
    ASSERT_EQ(mz_zip_entry_write_open(zip, &file_info, 0, 0, "password"), MZ_OK);
    ASSERT_EQ(mz_zip_entry_write(zip, plaintext, sizeof(plaintext) - 1), (int32_t)sizeof(plaintext) - 1);
    ASSERT_EQ(mz_zip_entry_close(zip), MZ_OK);
    ASSERT_EQ(mz_zip_close(zip), MZ_OK);
    mz_zip_delete(&zip);

    mz_stream_mem_get_buffer(mem_stream, &zip_buffer);
    mz_stream_mem_get_buffer_length(mem_stream, &zip_buffer_length);
    archive.assign((const uint8_t *)zip_buffer, (const uint8_t *)zip_buffer + zip_buffer_length);
    ASSERT_EQ(mz_zip_reader_open_buffer(reader, archive.data(), (int32_t)archive.size(), 1), MZ_OK);
    ASSERT_EQ(mz_zip_reader_goto_first_entry(reader), MZ_OK);
    ASSERT_EQ(mz_zip_reader_entry_get_info(reader, &read_info), MZ_OK);
    ASSERT_EQ(read_info->aes_version, 2);
    ASSERT_NE(read_info->flag & MZ_ZIP_FLAG_DATA_DESCRIPTOR, 0);
    ASSERT_GE(read_info->compressed_size, 10);

    ASSERT_GE(archive.size(), 30);
    data_offset = 30 + archive[26] + (archive[27] << 8) + archive[28] + (archive[29] << 8);
    tag_offset = data_offset + (size_t)read_info->compressed_size - 10;
    ASSERT_LT(data_offset + 18, archive.size());
    ASSERT_LT(tag_offset + 3, archive.size());

    mz_zip_reader_close(reader);
    mz_zip_reader_delete(&reader);
    mz_stream_mem_close(mem_stream);
    mz_stream_mem_delete(&mem_stream);

    EXPECT_EQ(read_aes_entry(archive, &contents), MZ_OK);
    EXPECT_EQ(contents, plaintext);
    EXPECT_EQ(read_aes_entry_with_descriptor(archive), MZ_OK);
    EXPECT_EQ(read_aes_entry_with_descriptor(archive, 1), MZ_OK);
    EXPECT_EQ(read_aes_entry_with_descriptor(archive, 1, nullptr), MZ_OK);

    contents.clear();
    std::vector<uint8_t> tampered_tag = archive;
    tampered_tag[tag_offset] ^= 1;
    EXPECT_EQ(read_aes_entry(tampered_tag, &contents), MZ_CRC_ERROR);
    EXPECT_EQ(contents, plaintext);

    tampered_tag[tag_offset] = 'P';
    tampered_tag[tag_offset + 1] = 'K';
    tampered_tag[tag_offset + 2] = 7;
    tampered_tag[tag_offset + 3] = 8;
    EXPECT_EQ(read_aes_entry_with_descriptor(tampered_tag), MZ_CRC_ERROR);

    contents.clear();
    std::vector<uint8_t> tampered_ciphertext = archive;
    tampered_ciphertext[data_offset + 18] ^= 1;
    EXPECT_EQ(read_aes_entry(tampered_ciphertext, &contents), MZ_CRC_ERROR);
    EXPECT_NE(contents, plaintext);

    contents.clear();
    EXPECT_EQ(read_aes_entry(archive, &contents, 1), MZ_OK);
    EXPECT_EQ(contents.size(), 1);

    reader = mz_zip_reader_create();
    ASSERT_NE(reader, nullptr);
    ASSERT_EQ(mz_zip_reader_open_buffer(reader, archive.data(), (int32_t)archive.size(), 1), MZ_OK);
    ASSERT_EQ(mz_zip_reader_goto_first_entry(reader), MZ_OK);
    mz_zip_reader_set_password(reader, "password");
    ASSERT_EQ(mz_zip_reader_entry_open(reader), MZ_OK);
    char first_byte = 0;
    ASSERT_EQ(mz_zip_reader_entry_read(reader, &first_byte, 1), 1);
    EXPECT_EQ(mz_zip_reader_goto_first_entry(reader), MZ_OK);
    mz_zip_reader_close(reader);
    ASSERT_EQ(mz_zip_reader_open_buffer(reader, tampered_ciphertext.data(), (int32_t)tampered_ciphertext.size(), 1),
              MZ_OK);
    ASSERT_EQ(mz_zip_reader_goto_first_entry(reader), MZ_OK);
    ASSERT_EQ(mz_zip_reader_entry_open(reader), MZ_OK);
    char buffer[64];
    ASSERT_EQ(mz_zip_reader_entry_read(reader, buffer, sizeof(buffer)), (int32_t)sizeof(plaintext) - 1);
    EXPECT_EQ(mz_zip_reader_goto_next_entry(reader), MZ_CRC_ERROR);
    mz_zip_reader_close(reader);
    mz_zip_reader_delete(&reader);
}

#  if defined(HAVE_ZLIB) || defined(HAVE_LIBCOMP)
static void create_raw_aes_entry(const std::vector<uint8_t> &compressed, int64_t uncompressed_size,
                                 uint16_t aes_version, uint32_t crc, bool tamper_tag, std::vector<uint8_t> *archive) {
    void *encrypted = mz_stream_mem_create();
    void *aes = mz_stream_wzaes_create();
    void *mem = mz_stream_mem_create();
    void *zip = mz_zip_create();
    const void *buffer = nullptr;
    int64_t length = 0;
    mz_zip_file info = {};

    ASSERT_NE(encrypted, nullptr);
    ASSERT_NE(aes, nullptr);
    ASSERT_NE(mem, nullptr);
    ASSERT_NE(zip, nullptr);
    ASSERT_EQ(mz_stream_mem_open(encrypted, nullptr, MZ_OPEN_MODE_CREATE), MZ_OK);
    mz_stream_set_base(aes, encrypted);
    mz_stream_wzaes_set_password(aes, "password");
    mz_stream_wzaes_set_strength(aes, MZ_AES_STRENGTH_256);
    ASSERT_EQ(mz_stream_open(aes, nullptr, MZ_OPEN_MODE_WRITE), MZ_OK);
    ASSERT_EQ(mz_stream_write(aes, compressed.data(), (int32_t)compressed.size()), (int32_t)compressed.size());
    ASSERT_EQ(mz_stream_close(aes), MZ_OK);
    mz_stream_mem_get_buffer(encrypted, &buffer);
    mz_stream_mem_get_buffer_length(encrypted, &length);
    if (tamper_tag)
        ((uint8_t *)buffer)[length - 1] ^= 1;

    ASSERT_EQ(mz_stream_mem_open(mem, nullptr, MZ_OPEN_MODE_CREATE), MZ_OK);
    ASSERT_EQ(mz_zip_open(zip, mem, MZ_OPEN_MODE_WRITE), MZ_OK);
    info.filename = "contents.txt";
    info.flag = MZ_ZIP_FLAG_ENCRYPTED | MZ_ZIP_FLAG_DATA_DESCRIPTOR;
    info.compression_method = MZ_COMPRESS_METHOD_DEFLATE;
    info.aes_version = aes_version;
    info.aes_strength = MZ_AES_STRENGTH_256;
    ASSERT_EQ(mz_zip_entry_write_open(zip, &info, 6, 1, nullptr), MZ_OK);
    ASSERT_EQ(mz_zip_entry_write(zip, buffer, (int32_t)length), length);
    ASSERT_EQ(mz_zip_entry_write_close(zip, crc, -1, uncompressed_size), MZ_OK);
    ASSERT_EQ(mz_zip_close(zip), MZ_OK);
    mz_stream_mem_get_buffer(mem, &buffer);
    mz_stream_mem_get_buffer_length(mem, &length);
    archive->assign((const uint8_t *)buffer, (const uint8_t *)buffer + length);

    mz_zip_delete(&zip);
    mz_stream_mem_delete(&mem);
    mz_stream_wzaes_delete(&aes);
    mz_stream_mem_delete(&encrypted);
}

TEST(zip_reader_aes, verifies_deflated_entries_at_eof) {
    /* Raw deflate for "a", followed by bytes the decompressor does not consume. */
    const std::vector<uint8_t> compressed = {0x4b, 0x04, 0x00, 0, 0, 0, 0, 0};
    std::vector<uint8_t> archive;
    std::string contents;

    create_raw_aes_entry(compressed, 1, 2, 0, false, &archive);
    ASSERT_FALSE(archive.empty());
    EXPECT_EQ(read_aes_entry(archive, &contents), MZ_OK);
    EXPECT_EQ(contents, "a");
    EXPECT_EQ(read_aes_entry_with_descriptor(archive), MZ_OK);

    create_raw_aes_entry(compressed, 1, 2, 0, true, &archive);
    contents.clear();
    EXPECT_EQ(read_aes_entry(archive, &contents), MZ_CRC_ERROR);
    EXPECT_EQ(contents, "a");

    /* An inflated size must not turn a read to EOF into an intentional partial read. */
    create_raw_aes_entry(compressed, 2, 2, 0, true, &archive);
    contents.clear();
    EXPECT_EQ(read_aes_entry(archive, &contents), MZ_CRC_ERROR);
    EXPECT_EQ(contents, "a");

    contents.clear();
    EXPECT_EQ(read_aes_entry(archive, &contents, 64), MZ_CRC_ERROR);
    EXPECT_EQ(contents, "a");
}

TEST(zip_reader_aes, preserves_partial_deflated_reads) {
    const std::vector<uint8_t> compressed = {0x4b, 0x4c, 0x4c, 0x4c, 0x04, 0x00};
    std::vector<uint8_t> archive;
    std::string contents;

    create_raw_aes_entry(compressed, 4, 1, 0xad98e545, false, &archive);
    ASSERT_FALSE(archive.empty());
    EXPECT_EQ(read_aes_entry(archive, &contents, 1), MZ_OK);
    EXPECT_EQ(contents, "a");
    contents.clear();
    EXPECT_EQ(read_aes_entry(archive, &contents), MZ_OK);
    EXPECT_EQ(contents, "aaaa");
}

TEST(zip_reader_aes, verifies_aes1_crc_after_deflation) {
    const std::vector<uint8_t> compressed = {0x4b, 0x04, 0x00};
    std::vector<uint8_t> archive;
    std::string contents;

    create_raw_aes_entry(compressed, 1, 1, 0xe8b7be43, false, &archive);
    ASSERT_FALSE(archive.empty());
    EXPECT_EQ(read_aes_entry(archive, &contents), MZ_OK);
    EXPECT_EQ(contents, "a");

    create_raw_aes_entry(compressed, 1, 1, 0xe8b7be42, false, &archive);
    contents.clear();
    EXPECT_EQ(read_aes_entry(archive, &contents), MZ_CRC_ERROR);
    EXPECT_EQ(contents, "a");
}
#  endif
#endif

#ifdef HAVE_PKCRYPT
TEST(zip_reader_pkcrypt, verifies_crc_on_close) {
    const char plaintext[] = "encrypted contents";
    void *mem = mz_stream_mem_create();
    void *zip = mz_zip_create();
    mz_zip_file info = {};
    const void *buffer = nullptr;
    int64_t data_offset = 0;
    char contents[sizeof(plaintext)];

    ASSERT_NE(mem, nullptr);
    ASSERT_NE(zip, nullptr);
    ASSERT_EQ(mz_stream_mem_open(mem, nullptr, MZ_OPEN_MODE_CREATE), MZ_OK);
    ASSERT_EQ(mz_zip_open(zip, mem, MZ_OPEN_MODE_WRITE), MZ_OK);
    info.filename = "contents.txt";
    info.modified_date = time(nullptr);
    info.compression_method = MZ_COMPRESS_METHOD_STORE;
    ASSERT_EQ(mz_zip_entry_write_open(zip, &info, 0, 0, "password"), MZ_OK);
    data_offset = mz_stream_tell(mem);
    ASSERT_EQ(mz_zip_entry_write(zip, plaintext, sizeof(plaintext)), (int32_t)sizeof(plaintext));
    ASSERT_EQ(mz_zip_entry_close(zip), MZ_OK);
    ASSERT_EQ(mz_zip_close(zip), MZ_OK);

    for (int tamper = 0; tamper <= 1; tamper++) {
        mz_stream_mem_get_buffer(mem, &buffer);
        if (tamper)
            ((uint8_t *)buffer)[data_offset] ^= 1;
        ASSERT_EQ(mz_zip_open(zip, mem, MZ_OPEN_MODE_READ), MZ_OK);
        ASSERT_EQ(mz_zip_goto_first_entry(zip), MZ_OK);
        ASSERT_EQ(mz_zip_entry_read_open(zip, 0, "password"), MZ_OK);
        ASSERT_EQ(mz_zip_entry_read(zip, contents, sizeof(contents)), (int32_t)sizeof(contents));
        EXPECT_EQ(mz_zip_entry_close(zip), tamper ? MZ_CRC_ERROR : MZ_OK);
        ASSERT_EQ(mz_zip_close(zip), MZ_OK);
    }

    mz_zip_delete(&zip);
    mz_stream_mem_delete(&mem);
}
#endif

#if !defined(_WIN32)
#  include <sys/stat.h>
#  include <unistd.h>
#endif

#ifdef HAVE_CRYPT_BACKEND
TEST(zip_reader_hash, rejects_oversized_digest) {
    const uint8_t hash_extrafield[] = {
        0x51,         0x1a, 0x04, 0x00, /* Hash extra-field header and payload size. */
        MZ_HASH_SHA1, 0x00, 0x01, 0x01  /* SHA-1 with a claimed 257-byte digest. */
    };
    const void *zip_buffer = nullptr;
    void *mem_stream = mz_stream_mem_create();
    void *writer = mz_zip_writer_create();
    void *reader = mz_zip_reader_create();
    mz_zip_file file_info = {};
    int64_t zip_buffer_length = 0;

    ASSERT_NE(mem_stream, nullptr);
    ASSERT_NE(writer, nullptr);
    ASSERT_NE(reader, nullptr);
    ASSERT_EQ(mz_stream_mem_open(mem_stream, nullptr, MZ_OPEN_MODE_CREATE), MZ_OK);
    ASSERT_EQ(mz_zip_writer_open(writer, mem_stream, 0), MZ_OK);

    file_info.filename = "oversized-hash/";
    file_info.version_madeby = (MZ_HOST_SYSTEM_UNIX << 8) | MZ_VERSION_MADEBY_ZIP_VERSION;
    file_info.compression_method = MZ_COMPRESS_METHOD_STORE;
    file_info.external_fa = (uint32_t)(0040755 << 16);
    file_info.extrafield = hash_extrafield;
    file_info.extrafield_size = sizeof(hash_extrafield);
    ASSERT_EQ(mz_zip_writer_add_info(writer, nullptr, nullptr, &file_info), MZ_OK);
    ASSERT_EQ(mz_zip_writer_close(writer), MZ_OK);

    mz_stream_mem_get_buffer(mem_stream, &zip_buffer);
    mz_stream_mem_get_buffer_length(mem_stream, &zip_buffer_length);
    ASSERT_EQ(mz_zip_reader_open_buffer(reader, (const uint8_t *)zip_buffer, zip_buffer_length, 1), MZ_OK);
    ASSERT_EQ(mz_zip_reader_goto_first_entry(reader), MZ_OK);
    EXPECT_EQ(mz_zip_reader_entry_open(reader), MZ_FORMAT_ERROR);
    EXPECT_EQ(mz_zip_reader_entry_open(reader), MZ_FORMAT_ERROR);

    mz_zip_reader_close(reader);
    mz_zip_reader_delete(&reader);
    mz_zip_writer_delete(&writer);
    mz_stream_mem_close(mem_stream);
    mz_stream_mem_delete(&mem_stream);
}
#endif

#if !defined(_WIN32) && defined(HAVE_SYMLINK)

class zip_reader_symlink_test : public ::testing::Test {
  protected:
    void SetUp() override {
        char temp_path[] = "/tmp/minizip-extract-test-XXXXXX";
        char *root = nullptr;
        mz_zip_file file_info;

        original_directory = getcwd(nullptr, 0);
        ASSERT_NE(original_directory, nullptr);

        root = mkdtemp(temp_path);
        ASSERT_NE(root, nullptr);

        root_path = root;
        archive = root_path + "/archive.zip";
        destination = root_path + "/destination";
        outside = root_path + "/outside";
        pivot = destination + "/pivot";
        escaped_directory = outside + "/newdir";

        memset(&file_info, 0, sizeof(file_info));
        file_info.filename = "pivot/newdir/";
        file_info.version_madeby = MZ_VERSION_MADEBY;
        file_info.compression_method = MZ_COMPRESS_METHOD_STORE;
        file_info.flag = MZ_ZIP_FLAG_UTF8;

        writer = mz_zip_writer_create();
        ASSERT_NE(writer, nullptr);
        ASSERT_EQ(mz_zip_writer_open_file(writer, archive.c_str(), 0, 0), MZ_OK);
        ASSERT_EQ(mz_zip_writer_add_info(writer, nullptr, nullptr, &file_info), MZ_OK);
        ASSERT_EQ(mz_zip_writer_close(writer), MZ_OK);
        mz_zip_writer_delete(&writer);

        ASSERT_EQ(mkdir(destination.c_str(), 0755), 0);
        ASSERT_EQ(mkdir(outside.c_str(), 0755), 0);
        ASSERT_EQ(symlink("../outside", pivot.c_str()), 0);
    }

    void TearDown() override {
        if (reader) {
            mz_zip_reader_close(reader);
            mz_zip_reader_delete(&reader);
        }
        if (writer) {
            mz_zip_writer_close(writer);
            mz_zip_writer_delete(&writer);
        }
        if (original_directory) {
            chdir(original_directory);
            free(original_directory);
        }

        unlink(pivot.c_str());
        unlink(archive.c_str());
        rmdir(escaped_directory.c_str());
        rmdir(outside.c_str());
        rmdir(destination.c_str());
        rmdir(root_path.c_str());
    }

    void *reader = nullptr;
    void *writer = nullptr;
    char *original_directory = nullptr;
    std::string root_path;
    std::string archive;
    std::string destination;
    std::string outside;
    std::string pivot;
    std::string escaped_directory;
};

TEST_F(zip_reader_symlink_test, rejects_directory_entry_with_destination) {
    reader = mz_zip_reader_create();
    ASSERT_NE(reader, nullptr);
    ASSERT_EQ(mz_zip_reader_open_file(reader, archive.c_str()), MZ_OK);

    EXPECT_NE(mz_zip_reader_save_all(reader, destination.c_str()), MZ_OK);
    EXPECT_NE(mz_os_is_dir(escaped_directory.c_str()), MZ_OK);
}

TEST_F(zip_reader_symlink_test, rejects_directory_entry_without_destination) {
    reader = mz_zip_reader_create();
    ASSERT_NE(reader, nullptr);
    ASSERT_EQ(mz_zip_reader_open_file(reader, archive.c_str()), MZ_OK);
    ASSERT_EQ(chdir(destination.c_str()), 0);

    EXPECT_NE(mz_zip_reader_save_all(reader, nullptr), MZ_OK);
    EXPECT_NE(mz_os_is_dir(escaped_directory.c_str()), MZ_OK);
}

class zip_reader_confinement_test : public ::testing::Test {
  protected:
    void SetUp() override {
        char temp_path[] = "/tmp/minizip-confine-test-XXXXXX";
        char *root = nullptr;

        original_directory = getcwd(nullptr, 0);
        ASSERT_NE(original_directory, nullptr);

        root = mkdtemp(temp_path);
        ASSERT_NE(root, nullptr);

        root_path = root;
        archive = root_path + "/archive.zip";
        destination = root_path + "/destination";
        outside = root_path + "/outside";

        ASSERT_EQ(mkdir(destination.c_str(), 0755), 0);
        ASSERT_EQ(mkdir(outside.c_str(), 0755), 0);
    }

    void TearDown() override {
        if (reader) {
            mz_zip_reader_close(reader);
            mz_zip_reader_delete(&reader);
        }
        if (original_directory) {
            chdir(original_directory);
            free(original_directory);
        }
        /* Extraction may create a nested tree under the destination, so remove it recursively */
        std::string command = "rm -rf " + root_path;
        (void)system(command.c_str());
    }

    /* Write a single stored entry with the given name and contents */
    void write_entry(const char *filename, const char *contents) {
        mz_zip_file file_info;
        void *writer = mz_zip_writer_create();
        ASSERT_NE(writer, nullptr);

        memset(&file_info, 0, sizeof(file_info));
        file_info.filename = filename;
        file_info.version_madeby = MZ_VERSION_MADEBY;
        file_info.compression_method = MZ_COMPRESS_METHOD_STORE;
        file_info.flag = MZ_ZIP_FLAG_UTF8;

        ASSERT_EQ(mz_zip_writer_open_file(writer, archive.c_str(), 0, 0), MZ_OK);
        ASSERT_EQ(mz_zip_writer_add_buffer(writer, (void *)contents, (int32_t)strlen(contents), &file_info), MZ_OK);
        ASSERT_EQ(mz_zip_writer_close(writer), MZ_OK);
        mz_zip_writer_delete(&writer);
    }

    void *reader = nullptr;
    char *original_directory = nullptr;
    std::string root_path;
    std::string archive;
    std::string destination;
    std::string outside;
};

TEST_F(zip_reader_confinement_test, does_not_write_through_dangling_symlink) {
    std::string planted = destination + "/link_name";
    std::string escaped = outside + "/pwned.txt";

    /* Pre-plant a dangling symlink whose target does not yet exist */
    ASSERT_EQ(symlink(escaped.c_str(), planted.c_str()), 0);

    write_entry("link_name", "escape");

    reader = mz_zip_reader_create();
    ASSERT_NE(reader, nullptr);
    ASSERT_EQ(mz_zip_reader_open_file(reader, archive.c_str()), MZ_OK);
    EXPECT_EQ(mz_zip_reader_save_all(reader, destination.c_str()), MZ_OK);

    /* Extraction must not follow the symlink to write outside the destination */
    EXPECT_NE(mz_os_file_exists(escaped.c_str()), MZ_OK);
    EXPECT_NE(mz_os_is_symlink(planted.c_str()), MZ_OK);
    EXPECT_EQ(mz_os_file_exists(planted.c_str()), MZ_OK);

    unlink(planted.c_str());
    unlink(archive.c_str());
}

/* A drive-letter-shaped prefix combined with doubled separators must not
   escape the destination either (#1044) */
TEST_F(zip_reader_confinement_test, rejects_doubled_separator_drive_escape) {
    write_entry("//:/../pwned.txt", "escape");

    reader = mz_zip_reader_create();
    ASSERT_NE(reader, nullptr);
    ASSERT_EQ(mz_zip_reader_open_file(reader, archive.c_str()), MZ_OK);
    EXPECT_EQ(mz_zip_reader_save_all(reader, destination.c_str()), MZ_OK);
    std::string escaped = outside + "/pwned.txt";
    EXPECT_NE(mz_os_file_exists(escaped.c_str()), MZ_OK);
    /* Confirm the entry actually resolved inside the destination, not just
       that it avoided the specific escape path above */
    std::string expected = destination + "/pwned.txt";
    EXPECT_EQ(mz_os_file_exists(expected.c_str()), MZ_OK);
    unlink(expected.c_str());
    unlink(archive.c_str());
}
#endif

#if !defined(_WIN32)
/* A crafted archive must not produce a setuid file on extraction */
TEST(zip_reader_attribs, strips_setuid_bits) {
    char destination[] = "/tmp/minizip-attribs-test-XXXXXX";
    ASSERT_NE(mkdtemp(destination), nullptr);

    std::string archive = std::string(destination) + "/archive.zip";
    std::string extracted = std::string(destination) + "/setuid_entry";

    mz_zip_file file_info;
    memset(&file_info, 0, sizeof(file_info));
    file_info.filename = "setuid_entry";
    file_info.version_madeby = (MZ_HOST_SYSTEM_UNIX << 8) | MZ_VERSION_MADEBY_ZIP_VERSION;
    file_info.compression_method = MZ_COMPRESS_METHOD_STORE;
    file_info.flag = MZ_ZIP_FLAG_UTF8;
    file_info.external_fa = (uint32_t)((S_ISUID | S_ISGID | S_ISVTX | 0755) << 16);

    void *writer = mz_zip_writer_create();
    ASSERT_NE(writer, nullptr);
    ASSERT_EQ(mz_zip_writer_open_file(writer, archive.c_str(), 0, 0), MZ_OK);
    ASSERT_EQ(mz_zip_writer_add_buffer(writer, (void *)"data", 4, &file_info), MZ_OK);
    ASSERT_EQ(mz_zip_writer_close(writer), MZ_OK);
    mz_zip_writer_delete(&writer);

    void *reader = mz_zip_reader_create();
    ASSERT_NE(reader, nullptr);
    ASSERT_EQ(mz_zip_reader_open_file(reader, archive.c_str()), MZ_OK);
    EXPECT_EQ(mz_zip_reader_save_all(reader, destination), MZ_OK);
    mz_zip_reader_close(reader);
    mz_zip_reader_delete(&reader);

    struct stat entry_stat;
    memset(&entry_stat, 0, sizeof(entry_stat));
    ASSERT_EQ(stat(extracted.c_str(), &entry_stat), 0);

    /* The special bits are stripped while the ordinary permission bits are kept */
    EXPECT_EQ(entry_stat.st_mode & (S_ISUID | S_ISGID | S_ISVTX), 0u);
    EXPECT_EQ(entry_stat.st_mode & 0777, 0755u);

    unlink(extracted.c_str());
    unlink(archive.c_str());
    rmdir(destination);
}
#endif
