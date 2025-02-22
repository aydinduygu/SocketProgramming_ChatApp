import java.io.Serializable;
import java.security.PublicKey;

public class Request implements Serializable {

    private long id;
    private String userName;
    private String password;
    private String clientServerPortNumber;
    private String searchedUser;
    private PublicKey rsaPublicKey;

    /*
    * 1-register
    * 2-login
    * 3-hello
    * 4-message
    * 5-logout
    * */
    private int requestType;

    public Request(String userName, String password, String clientServerPortNumber, PublicKey rsaPublicKey, int requestType) {
        this.userName = userName;
        this.password = password;
        this.clientServerPortNumber = clientServerPortNumber;
        this.rsaPublicKey = rsaPublicKey;
        this.requestType = requestType;
    }

    public Request(String userName, String password, int requestType, String clientServerPortNumber) {
        this.userName = userName;
        this.password = password;
        this.requestType=requestType;
        this.clientServerPortNumber = clientServerPortNumber;

    }
    public Request(String userName, int requestType) {
        this.requestType=requestType;
        this.searchedUser = userName;

    }

    public String getSearchedUser() {
        return searchedUser;
    }

    public String getUserName() {
        return userName;
    }

    public void setUserName(String userName) {
        this.userName = userName;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public int getRequestType() {
        return requestType;
    }

    public void setRequestType(int requestType) {
        this.requestType = requestType;
    }

    public long getId() {
        return id;
    }

    public String getClientServerPortNumber() {
        return clientServerPortNumber;
    }
}
