package org.wso2.carbon.identity.ask.password.mgt.listener;

import org.wso2.carbon.identity.application.common.model.User;
import org.wso2.carbon.identity.ask.password.mgt.internal.AskPasswordNotificationManagerComponent;
import org.wso2.carbon.identity.core.AbstractIdentityUserOperationEventListener;
import org.wso2.carbon.identity.core.model.IdentityErrorMsgContext;
import org.wso2.carbon.identity.core.util.IdentityCoreConstants;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.event.IdentityEventException;
import org.wso2.carbon.identity.event.services.IdentityEventService;
import org.wso2.carbon.identity.mgt.IdentityMgtConfig;
import org.wso2.carbon.identity.mgt.dto.UserIdentityClaimsDO;
import org.wso2.carbon.identity.mgt.store.UserIdentityDataStore;
import org.wso2.carbon.identity.recovery.IdentityRecoveryConstants;
import org.wso2.carbon.registry.core.utils.UUIDGenerator;
import org.wso2.carbon.user.core.UserCoreConstants;
import org.wso2.carbon.user.core.UserStoreException;
import org.wso2.carbon.user.core.UserStoreManager;
import org.wso2.carbon.user.core.util.UserCoreUtil;

public class AskPasswordMgtEventListener extends AbstractIdentityUserOperationEventListener {

    private UserIdentityDataStore module;

    public AskPasswordMgtEventListener() {

        module = (IdentityMgtConfig.getInstance(AskPasswordNotificationManagerComponent.getRealmService().
                getBootstrapRealmConfiguration())).getIdentityDataStore();
//        module = IdentityMgtConfig.getInstance().getIdentityDataStore();

    }

    public void init() {

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
    public boolean doPreAuthenticate(String userName, Object credential, UserStoreManager userStoreManager) throws UserStoreException {

        if (!isEnable()) {
            return true;
        }
        IdentityEventService eventMgtService = AskPasswordNotificationManagerComponent.getIdentityEventService();

        String domainName = userStoreManager.getRealmConfiguration().
                getUserStoreProperty(UserCoreConstants.RealmConfig.PROPERTY_DOMAIN_NAME);
        String usernameWithDomain = UserCoreUtil.addDomainToName(userName, domainName);
        User user = new User();
        user.setUserName(userName);
        user.setTenantDomain(domainName);
//        user.setUserStoreDomain(domainName);

        boolean isUserExistInCurrentDomain = userStoreManager.isExistingUser(usernameWithDomain);
        if (isUserExistInCurrentDomain) {
            UserIdentityClaimsDO userIdentityDTO = module.load(userName, userStoreManager);
            if (userIdentityDTO.getUserIdentityDataMap().containsKey(IdentityRecoveryConstants.ACCOUNT_STATE_CLAIM_URI)) {
                if (userIdentityDTO.getUserIdentityDataMap().get(IdentityRecoveryConstants.ACCOUNT_STATE_CLAIM_URI).
                        equals(IdentityRecoveryConstants.PENDING_ASK_PASSWORD)) {
                    IdentityErrorMsgContext customErrorMessageContext = new IdentityErrorMsgContext(
                            IdentityCoreConstants.ADMIN_FORCED_USER_PASSWORD_RESET_VIA_EMAIL_LINK_ERROR_CODE);
                    IdentityUtil.setIdentityErrorMsg(customErrorMessageContext);
                    IdentityEventException exception = new IdentityEventException(
                            IdentityCoreConstants.ADMIN_FORCED_USER_PASSWORD_RESET_VIA_EMAIL_LINK_ERROR_CODE);
                    throw new UserStoreException(exception.getMessage(), exception);
                }
                if (userIdentityDTO.getUserIdentityDataMap().get(IdentityRecoveryConstants.ACCOUNT_STATE_CLAIM_URI).
                        equals(IdentityRecoveryConstants.PENDING_SELF_REGISTRATION)) {
                    IdentityErrorMsgContext customErrorMessageContext = new IdentityErrorMsgContext(
                            IdentityCoreConstants.USER_ACCOUNT_NOT_CONFIRMED_ERROR_CODE);
                    IdentityUtil.setIdentityErrorMsg(customErrorMessageContext);
                    IdentityEventException exception = new IdentityEventException(
                            IdentityCoreConstants.USER_ACCOUNT_NOT_CONFIRMED_ERROR_CODE);
                    throw new UserStoreException(exception.getMessage(), exception);
                }
            }
        }
        return true;
    }

}
