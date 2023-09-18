#if defined(__linux__)
/* doc:start:linux-APPKEY-path */
#define EX_SSS_D_KEY_INPUT_FILE_DIR "/tmp/configuration/"
#define EX_SSS_D_KEY_INPUT_FILE_PATH EX_SSS_D_KEY_INPUT_FILE_DIR "plain_dkey_input.txt"
/* doc:end:linux-APPKEY-path */
#elif defined(_MSC_VER)
/* doc:start:windows-APPKEY-path */
#define EX_SSS_D_KEY_INPUT_FILE_DIR "C:\\nxp\\configuration\\"
#define EX_SSS_D_KEY_INPUT_FILE_PATH EX_SSS_D_KEY_INPUT_FILE_DIR "plain_dkey_input.txt"
/* doc:end:windows-APPKEY-path */
#else
/* Not defined / avialable */
#endif

sss_status_t ex_sss_util_get_app_keys_from_path(uint8_t *appkey, size_t *appkey_len);
static sss_status_t read_app_keys_from_file(const char *appkey_file_path, uint8_t *appkey, size_t *appkey_len);
sss_status_t ex_sss_util_get_dkeyinput_from_path(uint8_t *uid, size_t uidLen, uint8_t *application_identifier, size_t application_identifier_len, uint8_t *system_identifier, size_t system_identifier_len);
static sss_status_t convert_string_into_integer(bool flag, char *stringin, uint8_t *intout, size_t intout_size);

int_main() {
    uint8_t getUid[EX_DIVERSIFY_UID_LEN] = EX_DIVERSIFY_INPUT_UID;
    size_t getUidLen  = sizeof(getUid);
    uint8_t getAid[EX_DIVERSIFY_AID_LEN]    = EX_DIVERSIFY_INPUT_AID;
    size_t getAidLen     = sizeof(getAid);
    uint8_t getSid[EX_DIVERSIFY_SID_LEN]    = EX_DIVERSIFY_INPUT_SID;
    size_t getSidLen     = sizeof(getSid);
    uint8_t diversifyInput[EX_DIVERSIFY_INPUT_SIZE] = {0};
    size_t diversifyInputLen = 0;
  
#if defined(EX_SSS_D_KEY_INPUT_FILE_PATH)
    status = ex_sss_util_get_dkeyinput_from_path(&getUid[0], getUidLen, &getAid[0], getAidLen, &getSid[0], getSidLen);
    if (status != kStatus_SSS_Success) {
        return status;
    }
#endif // EX_SSS_D_KEY_INPUT_FILE_PATH
}

sss_status_t ex_sss_util_get_app_keys_from_path(uint8_t *appkey, size_t *appkey_len)
{
    sss_status_t status  = kStatus_SSS_Fail;
    const char *filename = EX_SSS_APPKEY_FILE_PATH;
    FILE *fp             = NULL;
    LOG_D("Using File: %s", filename);

    if (strstr(filename, "..") != NULL) {
        LOG_W("Potential directory traversal");
    }

    fp = fopen(filename, "rb");
    if (fp != NULL) {
        // File exists. Get keys from file
        LOG_W("Using appkeys from:'%s' (FILE=%s)", filename, EX_SSS_APPKEY_FILE_PATH);
        if (0 != fclose(fp)) {
           LOG_E("Unable to close appkey file");
        }
        status = read_app_keys_from_file(filename, appkey, appkey_len);
    }
    else {
        // File does not exist. Check env variable
        char *appkey_path_env = NULL;
        #if defined(_MSC_VER)
            size_t sz = 0;
            _dupenv_s(&appkey_path_env, &sz, EX_SSS_BOOT_APPKEY_PATH_ENV);
        #else
            appkey_path_env = getenv(EX_SSS_BOOT_APPKEY_PATH_ENV);
        #endif //_MSC_VER

        if (appkey_path_env != NULL) {
            LOG_W("Using appkeys from:'%s' (ENV=%s)", appkey_path_env, EX_SSS_BOOT_APPKEY_PATH_ENV);
            status = read_app_keys_from_file(appkey_path_env, appkey, appkey_len);
            #if defined(_MSC_VER)
                free(appkey_path_env);
            #endif //_MSC_VER
        }
        else {
            LOG_I(
                "Using default appkey. "
                "You can use appkeys from file using ENV=%s",
                EX_SSS_BOOT_APPKEY_PATH_ENV);
        }
    }

    if (status != kStatus_SSS_Success) {
        LOG_D("Using default appkeys");
    }

    return status;
}

static sss_status_t read_app_keys_from_file(const char *appkey_file_path, uint8_t *appkey, size_t *appkey_len)
{
    sss_status_t status = kStatus_SSS_Fail;

    FILE *appkey_file = fopen(appkey_file_path, "r");

    if (strstr(appkey_file_path, "..") != NULL) {
        LOG_W("Potential directory traversal");
    }

    if (appkey_file == NULL) {
        LOG_E("Cannot open appkey file");
        status = kStatus_SSS_Fail;
        return status;
    }
    char file_data[1024];
    char *pdata      = &file_data[0];
    bool appkey_flag = false;

    while (fgets(pdata, sizeof(file_data), appkey_file)) {
        size_t i = 0, j = 0;

        /*Don't need leading spaces*/
        for (i = 0; i < strlen(pdata); i++) {
            char charac = pdata[i];
            if (!isspace(charac)) {
                break;
            }
        }

        /*Lines beginning with '#' are comments*/
        if (pdata[i] == '#') {
            continue;
        }

        /*Remove trailing comments*/
        for (j = 0; j < strlen(pdata); j++) {
            if (pdata[j] == '#') {
                pdata[j] = '\0';
                break;
            }
        }

        if (strncmp(&pdata[i], "APPKEY ", strlen("APPKEY ")) == 0) {
#if UNSECURE_LOGGING_OF_APP_KEYS
            LOG_I("%s", &pdata[i]);
#endif
            status = convert_string_into_integer_calculate_and_return_len(appkey_flag, &pdata[i], appkey, appkey_len);
            if (status != kStatus_SSS_Success) {
                if (0 != fclose(appkey_file)) {
                    LOG_E("Unable to close appkey file");
                }
                return status;
            }
            appkey_flag = true;
        }
        else {
            LOG_E("Unknown key type %s", &pdata[i]);
            status = kStatus_SSS_Fail;
            if (0 != fclose(appkey_file)) {
                LOG_E("Unable to close appkey file");
            }
            return status;
        }
    }

    if (0 != fclose(appkey_file)) {
        LOG_E("Unable to close appkey file");
        return kStatus_SSS_Fail;
    }
    return kStatus_SSS_Success;
}
#endif // EX_SSS_APPKEY_FILE_PATH

#ifdef EX_SSS_D_KEY_INPUT_FILE_PATH

sss_status_t ex_sss_util_get_dkeyinput_from_path(uint8_t *uid, size_t uidLen, uint8_t *application_identifier, size_t application_identifier_len, uint8_t *system_identifier, size_t system_identifier_len)
{
    sss_status_t status  = kStatus_SSS_Fail;
    const char *filename = EX_SSS_D_KEY_INPUT_FILE_PATH;
    FILE *fp             = NULL;
    LOG_D("Using File: %s", filename);

    if (strstr(filename, "..") != NULL) {
        LOG_W("Potential directory traversal");
    }

    fp = fopen(filename, "rb");
    if (fp != NULL) {
        // File exists. Get keys from file
        LOG_W("get inputs to derive dkey from:'%s' (FILE=%s)", filename, EX_SSS_D_KEY_INPUT_FILE_PATH);
        if (0 != fclose(fp)) {
           LOG_E("Unable to close dkey input file");
        }
        status = read_dkeyinput_file(filename, uid, uidLen, application_identifier, application_identifier_len, system_identifier, system_identifier_len);
    }
    else {
        // File does not exist. Check env variable
        char *appkey_path_env = NULL;
        #if defined(_MSC_VER)
            size_t sz = 0;
            _dupenv_s(&appkey_path_env, &sz, EX_SSS_BOOT_D_KEY_PATH_ENV);
        #else
            appkey_path_env = getenv(EX_SSS_BOOT_D_KEY_PATH_ENV);
        #endif //_MSC_VER

        if (appkey_path_env != NULL) {
            LOG_W("get inputs to derive dkey from:'%s' (ENV=%s)", appkey_path_env, EX_SSS_BOOT_D_KEY_PATH_ENV);
            status = read_dkeyinput_file(filename, uid, uidLen, application_identifier, application_identifier_len, system_identifier, system_identifier_len);
            #if defined(_MSC_VER)
                free(appkey_path_env);
            #endif //_MSC_VER
        }
        else {
            LOG_I(
                "Using default inputs to derive dkey. "
                "You can use get inputs to derive dkey from file using ENV=%s",
                EX_SSS_BOOT_D_KEY_PATH_ENV);
        }
    }

    if (status != kStatus_SSS_Success) {
        LOG_D("Using default get inputs to derive dkey");
    }

    return status;
}

static sss_status_t read_dkeyinput_file(const char *dkey_input_file_path, uint8_t *uid, size_t uidLen, uint8_t *application_identifier, size_t application_identifier_len, uint8_t *system_identifier, size_t system_identifier_len)
{
    sss_status_t status = kStatus_SSS_Fail;

    FILE *dkey_input_file = fopen(dkey_input_file_path, "r");

    if (strstr(dkey_input_file_path, "..") != NULL) {
        LOG_W("Potential directory traversal");
    }

    if (dkey_input_file == NULL) {
        LOG_E("Cannot open dkey input file");
        status = kStatus_SSS_Fail;
        return status;
    }
    char file_data[1024];
    char *pdata      = &file_data[0];
    bool uid_flag = false;
    bool aid_flag = false;
    bool sid_flag = false;

    while (fgets(pdata, sizeof(file_data), dkey_input_file)) {
        size_t i = 0, j = 0;

        /*Don't need leading spaces*/
        for (i = 0; i < strlen(pdata); i++) {
            char charac = pdata[i];
            if (!isspace(charac)) {
                break;
            }
        }

        /*Lines beginning with '#' are comments*/
        if (pdata[i] == '#') {
            continue;
        }

        /*Remove trailing comments*/
        for (j = 0; j < strlen(pdata); j++) {
            if (pdata[j] == '#') {
                pdata[j] = '\0';
                break;
            }
        }

        if (strncmp(&pdata[i], "UID ", strlen("UID ")) == 0) {
#if UNSECURE_LOGGING_OF_APP_KEYS
            LOG_I("%s", &pdata[i]);
#endif
            status = convert_string_into_integer(uid_flag, &pdata[i], uid, uidLen);
            if (status != kStatus_SSS_Success) {
                if (0 != fclose(dkey_input_file)) {
                    LOG_E("Unable to close dkey input file");
                }
                return status;
            }
            uid_flag = true;
        } else if (!(strncmp(&pdata[i], "AID ", strlen("AID ")))) {
#if UNSECURE_LOGGING_OF_APP_KEYS
            LOG_I("%s", &pdata[i]);
#endif
            status = convert_string_into_integer(aid_flag, &pdata[i], application_identifier, application_identifier_len);
            if (status != kStatus_SSS_Success) {
                if (0 != fclose(dkey_input_file)) {
                    LOG_E("Unable to close dkey input file");
                }
                return status;
            }
            aid_flag = true;
        } else if (!(strncmp(&pdata[i], "SID ", strlen("SID ")))) {
#if UNSECURE_LOGGING_OF_APP_KEYS
            LOG_I("%s", &pdata[i]);
#endif
            status = convert_string_into_integer(sid_flag, &pdata[i], system_identifier, system_identifier_len);
            if (status != kStatus_SSS_Success) {
                if (0 != fclose(dkey_input_file)) {
                    LOG_E("Unable to close dkey input file");
                }
                return status;
            }
            sid_flag = true;
        }
        else {
            LOG_E("Unknown key type %s", &pdata[i]);
            status = kStatus_SSS_Fail;
            if (0 != fclose(dkey_input_file)) {
                LOG_E("Unable to close dkey input file");
            }
            return status;
        }
    }

    if (0 != fclose(dkey_input_file)) {
        LOG_E("Unable to close dkey input file");
        return kStatus_SSS_Fail;
    }
    return kStatus_SSS_Success;
}

static sss_status_t convert_string_into_integer(bool flag, char *stringin, uint8_t *intout, size_t intout_size)
{
    sss_status_t status = kStatus_SSS_Success;
    size_t j            = 0;
    char charac          = stringin[j];
    if (flag) {
        LOG_E("Duplicate intout value");
        status = kStatus_SSS_Fail;
        return status;
    }
    while (!isspace(charac)) {
        if (j <= SIZE_MAX - 1) {
            j++;
        } else {
            LOG_E("Too long source string!");
            return status;
        }
        charac = stringin[j];
    }
    while (isspace(charac)) {
        if (j <= SIZE_MAX - 1) {
            j++;
        } else {
            LOG_E("Too long source string!");
            return status;
        }
        charac = stringin[j];
    }
    if (stringin[j] == '\0') {
        LOG_E("Invalid intout Value");
        status = kStatus_SSS_Fail;
        return status;
    }

    for (size_t count = 0; count < intout_size; count++) {
        if (sscanf(&stringin[j], "%2hhx", &intout[count]) != 1) {
            LOG_E("Cannot copy data");
            status = kStatus_SSS_Fail;
            return status;
        }

        if (j <= SIZE_MAX - 2) {
            j = j + 2;
        } else {
            LOG_E("Too long source string!");
            return status;
        }
    }

    return status;
}
