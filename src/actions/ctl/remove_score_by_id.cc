/*
 * ModSecurity, http://www.modsecurity.org/
 * Copyright (c) 2015 - 2021 Trustwave Holdings, Inc. (http://www.trustwave.com/)
 *
 * You may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * If any of the files related to licensing are missing or if you have any
 * other questions related to licensing please contact Trustwave Holdings, Inc.
 * directly using the email address security@modsecurity.org.
 *
 */

#include "src/actions/ctl/remove_score_by_id.h"

#include <string>

#include "modsecurity/transaction.h"
#include "src/utils/string.h"

namespace modsecurity {
namespace actions {
namespace ctl {


bool RemoveScoreById::init(std::string *error) {
    // m_parser_payload looks like "removeScoreById=123" (or ";"-separated ids).
    size_t pos = m_parser_payload.find('=');
    if (pos == std::string::npos) {
        error->assign("ctl:removeScoreById: missing '=' and rule id.");
        return false;
    }
    std::string what(m_parser_payload, pos + 1, m_parser_payload.size() - pos - 1);

    bool added = false;
    for (const std::string &a : utils::string::ssplit(what, ';')) {
        std::string b = modsecurity::utils::string::parserSanitizer(a);
        if (b.empty()) {
            continue;
        }
        try {
            m_ids.push_back(std::stod(b));
            added = true;
        } catch (...) {
            error->assign("ctl:removeScoreById: \"" + b +
                "\" is not a valid rule id.");
            return false;
        }
    }

    if (!added) {
        error->assign("ctl:removeScoreById: no rule id provided.");
        return false;
    }

    return true;
}


bool RemoveScoreById::evaluate(RuleWithActions *rule, Transaction *transaction) {
    for (double id : m_ids) {
        transaction->m_remove_score_by_id.push_back(id);
    }

    return true;
}


}  // namespace ctl
}  // namespace actions
}  // namespace modsecurity
