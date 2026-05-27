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

#include "src/actions/remove_set_var.h"

#include <string>
#include <vector>

#include "modsecurity/rules_set.h"
#include "modsecurity/transaction.h"
#include "modsecurity/rule.h"
#include "modsecurity/variable_value.h"
#include "src/utils/string.h"
#include "src/variables/global.h"
#include "src/variables/ip.h"
#include "src/variables/resource.h"
#include "src/variables/session.h"
#include "src/variables/tx.h"
#include "src/variables/user.h"
#include "src/variables/variable.h"


namespace modsecurity {
namespace actions {


namespace {


/* Strip a single pair of `/.../` delimiters if both are present. */
std::string stripRegexDelimiters(std::string s) {
    if (s.size() >= 2 && s.front() == '/' && s.back() == '/') {
        s.pop_back();
        s.erase(0, 1);
    }
    return s;
}


modsecurity::collection::Collection *collectionFor(Transaction *t,
        const std::string &name) {
    if (name == "tx")       return t->m_collections.m_tx_collection;
    if (name == "ip")       return t->m_collections.m_ip_collection;
    if (name == "global")   return t->m_collections.m_global_collection;
    if (name == "resource") return t->m_collections.m_resource_collection;
    if (name == "session")  return t->m_collections.m_session_collection;
    if (name == "user")     return t->m_collections.m_user_collection;
    return nullptr;
}


}  // namespace


bool RemoveSetVar::init(std::string *error) {
    /* The variable name is static (macros are not supported), so the
     * collection and the key regex are resolved and compiled once here. */
    if (m_string->containsMacro()) {
        error->assign("removesetvar does not support macro expansion in the "
            "variable name.");
        return false;
    }

    std::string expr = stripRegexDelimiters(m_string->evaluate());

    const size_t posDot = expr.find('.');
    if (posDot == std::string::npos) {
        error->assign("No collection found in removesetvar expression: " + expr);
        return false;
    }

    m_collectionName = utils::string::tolower(expr.substr(0, posDot));
    const std::string keyPattern = expr.substr(posDot + 1);

    m_regex = std::make_unique<Utils::Regex>(keyPattern, true);
    if (m_regex->hasError()) {
        error->assign("Invalid regular expression in removesetvar: " + keyPattern);
        return false;
    }

    return true;
}


bool RemoveSetVar::evaluate(RuleWithActions *rule, Transaction *t) {
    modsecurity::collection::Collection *col = collectionFor(t, m_collectionName);
    if (col == nullptr) {
        ms_dbg_a(t, 5, "Invalid collection in removesetvar expression: `" +
            m_collectionName + "' (must be tx, ip, global, resource, session, or user).");
        return true;
    }

    variables::KeyExclusions ke;
    std::vector<const VariableValue *> matches;
    col->resolveRegularExpression(m_regex.get(), &matches, ke);

    for (const VariableValue *vv : matches) {
        ms_dbg_a(t, 9, "Removing variable: " + m_collectionName + "." + vv->getKey());
        col->del(vv->getKey());
        delete vv;
    }

    return true;
}


}  // namespace actions
}  // namespace modsecurity
