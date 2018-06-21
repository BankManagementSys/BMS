
package RemoteTier;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

    /**
     *
     * @author Windows
     */
    public enum Constants {
        CONNECTOR();
        //the folllowing standard reasons for Leaving
        public static final String SICK_LEAVE="Medical reason";
        public static final String MATERNITY_LEAVE="Maternal reason";
        //this will be used to reference client person when nedded
        public static final String CLIENT_OBJECT_KEY="client";
        //the following constants will be called to indicate that there id no message
        public static final String NO_NEW_MESSAGE="no messages";
        //the following will be used to tell the clerk that his/herd account has been blokced
        public static final String BLOCKED_MESSAGE="Your Account has been Blocked. Report to your manager immediately";
        //the following constant will be used to flag a blocked clerk account
        public static final String ACCOUNT_BLOCKED="Blocked";
        //the following will be the key of the Manager object exported
        public static final String MANAGER_OBJECT_KEY="manager";
        //the following will be the key of the CLERK object exported
        public static final String CLERK_OBJECT_KEY="clerk";
        //the follwing message will be display when a clerk's leave permit has been approved.
        public static final String REQUEST_APPROVED="Your leave application has been approved";
        //the follwing message will be display when a clerk's leave permit has been denied.
        public static final String REQUEST_DENIED="Your leave application has been denied";
        //the following message will be displayed when a clerk tries to change his or her username to a username that is taken.
        public static final String USERNAME_EXISTS="This username already exists";
        //the following will reference the the key holding the data(in string format) the begining of leave day.
        public static final String REASON_FOR_APPLICATION="reason";
        //the following will reference the the key holding the data(in string format) the begining of leave day.
        public static final String FROM_DAY="from";
        //the following will reference the the key holding the data(in string format) the end of leave day.
        public static final String TO_DAY="to";
        //the following will reference the fullname key used to reference the full name of a leave permit apllicant
        public static final String FULLNAME="fullname";
        //the following value will reference the port through which the MANAGER object will be exported.
        public static final int MANAGER_OBJECT_PORT=54321;
        //the following value will reference the port through which the CLERK object will be exported.
        public static final int CLERK_OBJECT_PORT=102790;
        //the following value will reference the port in which the server will be listening
        public static final int SERVER_PORT=12345;
        //the DatabaseFileHandler object will be exported through this port.
        public static final int DATABASE_OBJECT_PORT=40562;
        //used to bind the DatabaseFileHandler object in rmi
        public static final String DATABASE_OBJECT_KEY="DatabaseFileHandler";
        //the following constant will be used to forcebily close clerk account access for security ressons.
        public static final String ROUTINE_MESSAGE="messages";
        //the folowing constant will be used to signal that no such employee exists
        public static final String INCORRECT_CREDENTIALS="Incorrect username or password";
        public static final String NO_SUCH_EMPLOYEE="No such employee";
        public static final String STATUS_DELIVERED="delivered";
        public static final String STATUS_PENDING="pending";
        //the following flag will be used to notify a message sender that its destination is online and the message has been delivered.
        public static final String MESSAGE_DELIVERED="Your message has been delivered";
        //the following flag will be used to notify a message sender that its destination is offline.
        public static final String DESTINATION_OFFLINE="The reciepent is offline";
        //when a clerk receives a message the folowing flag will be used to indecate the type fo message
        public static final String PEER_MESSAGE="peer Message";
        //when an employee receives a messge the following flag will be used to indicate the urgency of the message..
        public static final String URGENT="urgent";
        //when a new client is created and the manager recieves the approveal
        //request the following flag will be used to indicate what it is.
        public static final String APPROVE_CLIENT="Approve Client";
        //the following flag will be used to indicate that a clerk with the same credentials is currently in the system
        public static final String ALREADY_SIGNED_IN="already signed in";
        //START-the following constants are used to reference the personal information columns in the employee and client tbales
        public static final String EMPLOYEE_USERNAME="username";
        public static final String PASSWORD="password";
        public static final String TYPE_OF_EMPLOYEE="type";
        public static final String CLIENTS_TABLE_ACCOUNTS="accountNumber";
        public static final String FIRST_NAME="firstName";
        public static final String MIDDLE_NAME="middleName";
        public static final String LAST_NAME="lastName";
        public static final String SEX="sex";
        public static final String NATIONALITY="nationality";
        public static final String AGE="age";
        public static final String FIXED_PHONE="fixedPhoneAddress";
        public static final String MOBILE_PHONE="mobilePhoneAddress";
        public static final String KEBELE="kebele";
        public static final String WOREDA="woreda";
        public static final String HOUSE_NUMBER="houseNumber";
        public static final String SUB_CITY="subcity";
        public static final String REGION="region";
        public static final String ACCOUNT_BALANCE="accountBalance";
        public static final String INTEREST_RATE="interestRate";
        public static final String IMAGE="image";
        //END
//when the manager recieves a leave permit request this flag will be used to indicate what type of message it is to the manager UI.
        public static final String LEAVE_APPLICATION="Leave Application";
        //START-The following are the contents of actions logged when an activiy is done in the logger and transactions tables.
        public static final String LEAVE_PERMIT="Applied for leave";
        public static final String LOG_OUT="logged out";
        public static final String SENT_MESSAGE="sent message to ";
        public static final String PERSONAL_INFO="retrived personal information of ";
        public static final String ACTION_ROUTINE="routine";
        public static final String ACTION_SUSPICIOUS="suspicious";
        public static final String OBTAINED_MESSAGES="obtained messages";
        public static final String OBTAINED_ACTIVITY_ABOUT="retrieved activity report about ";
        public static final String OBTAINED_ACTIVITY_ABOUT_ALL="retrieved activity report about all employees";
        public static final String GENERATED_BANK_STATEMENT="generated bank statement for ";
        public static final String VERIFIED_ACCOUNTS="verified the latest accounts";
        public static final String ACTIVE_CONNECTIONS="obtained the list of active connections";
        public static final String SIGNED_IN="signed in to the system";
        public static final String DENIED_REQUEST="The manager denied the leave request of ";
        public static final String APPROVED_REQUEST="The manager approved the leave request of ";
        //END
        public static final String NO_SUCH_ACTIVE_ACCOUNT="No such active account";
        public static final String UNABLE_TO_PERFORM="Unable to perform action";
        public static final String SUCCESS_MESSAGE="Success";
        static private final String JDBC_LOCATION="jdbc:mysql://localhost:3306/sure";
        static private final String JDBC_USERNAME="root";
        static private final String JDBC_PASSWORD="sure";
        static public volatile Connection connector;
        static public volatile Statement state;
        static public ResultSet result;
        static public volatile PreparedStatement prepared;
        static{
            try {
                connector=DriverManager.getConnection(JDBC_LOCATION,JDBC_USERNAME,JDBC_PASSWORD);
                state=connector.createStatement(ResultSet.TYPE_SCROLL_INSENSITIVE,ResultSet.CONCUR_UPDATABLE);
            } catch (SQLException ex) {

            }

        }

    }


