use super::*;

impl ReplayState {
    #[cfg(test)]
    pub(crate) fn match_exchange(
        &mut self,
        identity: &ReplaySessionIdentity,
        command: &str,
        sql: Option<&str>,
        params: Option<&[RecordedMysqlValue]>,
    ) -> Option<MatchedExchange> {
        let case = self.active_case_id.clone();
        self.match_exchange_in_case(case.as_deref(), identity, command, sql, params)
    }

    #[cfg(test)]
    pub(in crate::protocols::replay::mysql) fn match_exchange_in_case(
        &mut self,
        case: Option<&str>,
        identity: &ReplaySessionIdentity,
        command: &str,
        sql: Option<&str>,
        params: Option<&[RecordedMysqlValue]>,
    ) -> Option<MatchedExchange> {
        self.match_exchange_in_case_preferred(case, identity, command, sql, params, None)
    }

    #[cfg(test)]
    pub(in crate::protocols::replay::mysql) fn match_exchange_in_case_preferred(
        &mut self,
        case: Option<&str>,
        identity: &ReplaySessionIdentity,
        command: &str,
        sql: Option<&str>,
        params: Option<&[RecordedMysqlValue]>,
        transaction: Option<TransactionMatch<'_>>,
    ) -> Option<MatchedExchange> {
        let observation = self.observe_mysql_request(case, identity, command, sql, params);
        self.select_mysql_exchange(
            case,
            identity,
            command,
            sql,
            params,
            transaction,
            &observation,
        )
    }
}
