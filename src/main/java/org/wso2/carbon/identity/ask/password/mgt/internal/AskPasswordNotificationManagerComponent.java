package org.wso2.carbon.identity.ask.password.mgt.internal;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.osgi.service.component.annotations.ReferencePolicy;
import org.wso2.carbon.identity.ask.password.mgt.listener.AskPasswordMgtEventListener;
import org.wso2.carbon.identity.event.services.IdentityEventService;
import org.wso2.carbon.user.core.listener.UserOperationEventListener;

@Component(
        name = "identity.governance.ask.password.notification.component",
        immediate = true
)
public class AskPasswordNotificationManagerComponent {

    private static final Log log = LogFactory.getLog(AskPasswordNotificationManagerComponent.class);

    private static IdentityEventService identityEventService;

    public static IdentityEventService getIdentityEventService() {

        return identityEventService;
    }

    @Activate
    protected void activate(ComponentContext context) {

        try {
            context.getBundleContext().registerService(UserOperationEventListener.class,
                    new AskPasswordMgtEventListener(), null);
        } catch (Exception exception) {
            log.error("Error occurred while activating ask password component", exception);
        }
    }

    @Deactivate
    protected void deactivate(ComponentContext context) {

        if (log.isDebugEnabled()) {
            log.debug("Ask password bundle is de-activated");
        }
    }

    protected void unsetIdentityEventService(IdentityEventService identityEventService) {

        AskPasswordNotificationManagerComponent.identityEventService = null;
    }

    @Reference(
            name = "EventMgtService",
            service = org.wso2.carbon.identity.event.services.IdentityEventService.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetIdentityEventService")
    protected void setIdentityEventService(IdentityEventService identityEventService) {

        AskPasswordNotificationManagerComponent.identityEventService = identityEventService;
    }
}
