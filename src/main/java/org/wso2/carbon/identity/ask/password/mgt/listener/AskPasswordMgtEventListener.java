package org.wso2.carbon.identity.ask.password.mgt.listener;

import org.apache.commons.lang.StringUtils;
import org.wso2.carbon.identity.core.AbstractIdentityUserOperationEventListener;
import org.wso2.carbon.identity.core.model.IdentityErrorMsgContext;
import org.wso2.carbon.identity.core.model.IdentityEventListenerConfig;
import org.wso2.carbon.identity.core.util.IdentityCoreConstants;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.event.IdentityEventException;
import org.wso2.carbon.identity.mgt.store.UserIdentityDataStore;
import org.wso2.carbon.identity.recovery.IdentityRecoveryConstants;
import org.wso2.carbon.user.core.UserStoreException;
import org.wso2.carbon.user.core.UserStoreManager;
import org.wso2.carbon.user.core.listener.UserOperationEventListener;

import java.util.Map;

public class AskPasswordMgtEventListener extends AbstractIdentityUserOperationEventListener {

    private UserIdentityDataStore module;
    private String accountStateClaimURI = "http://wso2.org/claims/identity/accountState";

    @Override
    public boolean isEnable() {

        IdentityEventListenerConfig identityEventListenerConfig = IdentityUtil.readEventListenerProperty
                (UserOperationEventListener.class.getName(), this.getClass().getName());

        if (identityEventListenerConfig == null) {
            return false;
        }
        if (StringUtils.isNotBlank(identityEventListenerConfig.getEnable())) {
            return Boolean.parseBoolean(identityEventListenerConfig.getEnable());
        } else {
            return false;
        }
    }

    @Override
    public int getExecutionOrderId() {

        int orderId = getOrderId();
        if (orderId != IdentityCoreConstants.EVENT_LISTENER_ORDER_ID) {
            return orderId;
        }
        return 15;
    }

    @Override
    public boolean doPreAuthenticate(String userName, Object credential, UserStoreManager userStoreManager)
            throws UserStoreException {

        if (!isEnable()) {
            return true;
        }
        Map<String, String> claimMap =
                userStoreManager.getUserClaimValues(userName, new String[]{accountStateClaimURI}, "default");
        String accountState = StringUtils.EMPTY;
        if (!claimMap.isEmpty()) {
            if (claimMap.containsKey(accountStateClaimURI)) {
                accountState = claimMap.get(accountStateClaimURI);
            }
        }
        if (StringUtils.isNotBlank(accountState)) {
            if (IdentityRecoveryConstants.PENDING_ASK_PASSWORD.equals(accountState)) {
                IdentityErrorMsgContext customErrorMessageContext = new IdentityErrorMsgContext(
                        IdentityCoreConstants.ADMIN_FORCED_USER_PASSWORD_RESET_VIA_EMAIL_LINK_ERROR_CODE);
                IdentityUtil.setIdentityErrorMsg(customErrorMessageContext);
                IdentityEventException exception = new IdentityEventException(
                        IdentityCoreConstants.ADMIN_FORCED_USER_PASSWORD_RESET_VIA_EMAIL_LINK_ERROR_CODE);
                throw new UserStoreException(exception.getMessage(), exception);
            } else if (IdentityRecoveryConstants.PENDING_SELF_REGISTRATION.equals(accountState)) {
                IdentityErrorMsgContext customErrorMessageContext = new IdentityErrorMsgContext(
                        IdentityCoreConstants.USER_ACCOUNT_NOT_CONFIRMED_ERROR_CODE);
                IdentityUtil.setIdentityErrorMsg(customErrorMessageContext);
                IdentityEventException exception = new IdentityEventException(
                        IdentityCoreConstants.USER_ACCOUNT_NOT_CONFIRMED_ERROR_CODE);
                throw new UserStoreException(exception.getMessage(), exception);
            }
        }
        return true;
    }
}
