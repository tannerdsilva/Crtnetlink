#include "Crtnetlink.h"

static int rtnl_receive(int fd, struct msghdr *msg, int flags)
{
	int len;

	do { 
		len = recvmsg(fd, msg, flags);
	} while (len < 0 && (errno == EINTR || errno == EAGAIN));

	if (len < 0) {
		perror("Netlink receive failed");
		return -errno;
	}

	if (len == 0) { 
		perror("EOF on netlink");
		return -ENODATA;
	}

	return len;
}

static int rtnl_recvmsg(int fd, struct msghdr *msg, char **answer)
{
	struct iovec *iov = msg->msg_iov;
	char *buf;
	int len;

	iov->iov_base = NULL;
	iov->iov_len = 0;

	len = rtnl_receive(fd, msg, MSG_PEEK | MSG_TRUNC);

	if (len < 0) {
		return len;
	}

	buf = malloc(len);

	if (!buf) {
		return -ENOMEM;
	}

	iov->iov_base = buf;
	iov->iov_len = len;

	len = rtnl_receive(fd, msg, 0);

	if (len < 0) {
		free(buf);
		return len;
	}

	*answer = buf;

	return len;
}

static void parse_rtattr(struct rtattr *tb[], int max, struct rtattr *rta, int len)
{
	memset(tb, 0, sizeof(struct rtattr *) * (max + 1));

	while (RTA_OK(rta, len)) {
		if (rta->rta_type <= max) {
			tb[rta->rta_type] = rta;
		}

		rta = RTA_NEXT(rta,len);
	}
}

int do_interface_dump_request(int sock) {
	// construct
	struct {
		struct nlmsghdr nlh;
		struct rtmsg rtm;
	} request;
	request.nlh.nlmsg_type = RTM_GETLINK;
	request.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
	request.nlh.nlmsg_len = sizeof(request);
	request.nlh.nlmsg_seq = time(NULL);
	// send
	return send(sock, &request, sizeof(request), 0);
}

int get_interface_dump_response(int sock, void(^hndlr)(struct nlmsghdr *)) {
	struct sockaddr_nl nladdr;
	struct iovec iov;
	struct msghdr msg = {
		.msg_name = &nladdr,
		.msg_namelen = sizeof(nladdr),
		.msg_iov = &iov,
		.msg_iovlen = 1,
	};
	
	char *buf;
	int dump_intr = 0;
	
	int status = rtnl_recvmsg(sock, &msg, &buf);
	
	struct nlmsghdr *h = (struct nlmsghdr*)buf;
	int msglen = status;
	while (NLMSG_OK(h, msglen)) {
		if (h->nlmsg_flags & NLM_F_DUMP_INTR) {
			free(buf);
			return -1;
		}
		
		if (nladdr.nl_pid != 0) {
			continue;
		}
		
		if (h->nlmsg_type == NLMSG_ERROR) {
			free(buf);
			return -2;
		}
		
		hndlr(h);
		
		h = NLMSG_NEXT(h, msglen);
	}
	free(buf);
	return status;
}

int read_interface(struct nlmsghdr *nl_header_answer, void(^hndlr)(struct ifinfomsg *ifin, struct rtattr *attrs[RTA_MAX+1])) {
	struct ifinfomsg *ifin = NLMSG_DATA(nl_header_answer);
	int len = nl_header_answer->nlmsg_len;
	struct rtattr *tb[IFLA_MAX+1];
	char buf[256];
	len -= NLMSG_LENGTH(sizeof(*ifin));
	if (len < 0) {
		return -1;
	}
	
	parse_rtattr(tb, RTA_MAX, IFLA_RTA(ifin), len);
	
	hndlr(ifin, tb);
	return 0;
}

void get_attribute_data_ifla(unsigned char family, struct rtattr *attrs[IFLA_MAX+1], int attrKey, char **buf) {
	if (attrs[attrKey]) {
		unsigned char *newBuff = (unsigned char*)RTA_DATA(attrs[attrKey]);
		(*buf) = malloc(32);
		snprintf((*buf), 32, "%02x:%02x:%02x:%02x:%02x:%02x", newBuff[0], newBuff[1], newBuff[2], newBuff[3], newBuff[4], newBuff[5]);
	} else {
		*buf = NULL;
	}
}

int do_address_dump_request_v4(int sock) {
	// construct
	struct {
		struct nlmsghdr nlh;
		struct rtmsg rtm;
	} request;
	request.nlh.nlmsg_type = RTM_GETADDR;
	request.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
	request.nlh.nlmsg_len = sizeof(request);
	request.nlh.nlmsg_seq = time(NULL);
	request.rtm.rtm_family = AF_INET;
	// send
	return send(sock, &request, sizeof(request), 0);
}

int do_address_dump_request_v6(int sock) {
	// construct
	struct {
		struct nlmsghdr nlh;
		struct rtmsg rtm;
	} request;
	request.nlh.nlmsg_type = RTM_GETADDR;
	request.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
	request.nlh.nlmsg_len = sizeof(request);
	request.nlh.nlmsg_seq = time(NULL);
	request.rtm.rtm_family = AF_INET6;
	// send
	return send(sock, &request, sizeof(request), 0);

}

size_t add_address_assignment_request_v4(char *buffer, const size_t current_len, const size_t max_len, int ifindex, uint32_t ip_address, int prefix_len) {
	struct {
		struct nlmsghdr nlh;
		struct ifaddrmsg ifa;
		char attrbuf[256];  // To store attributes
	} req;

	// Initialize the request
	memset(&req, 0, sizeof(req));

	// Fill the Netlink header
	req.nlh.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifaddrmsg));
	req.nlh.nlmsg_type = RTM_NEWADDR;
	req.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_EXCL;
	req.nlh.nlmsg_seq = 0;  // Sequence number can be set if tracking responses
	req.nlh.nlmsg_pid = getpid();

	// Fill the ifaddrmsg structure
	req.ifa.ifa_family = AF_INET;
	req.ifa.ifa_prefixlen = prefix_len;
	req.ifa.ifa_flags = IFA_F_PERMANENT;
	req.ifa.ifa_index = ifindex;
	req.ifa.ifa_scope = RT_SCOPE_UNIVERSE;

	// Prepare the attribute for the IP address
	struct rtattr *rta = (struct rtattr *)(req.attrbuf);
	rta->rta_type = IFA_LOCAL;
	rta->rta_len = RTA_LENGTH(sizeof(uint32_t));
	memcpy(RTA_DATA(rta), &ip_address, sizeof(uint32_t));
	req.nlh.nlmsg_len += rta->rta_len;

	// Check buffer size
	if (current_len + req.nlh.nlmsg_len > max_len) {
		return -1; // Not enough space
	}

	// Copy the request into the buffer
	memcpy(buffer + current_len, &req, req.nlh.nlmsg_len);

	// Return new buffer length
	return current_len + req.nlh.nlmsg_len;
}

size_t add_address_assignment_request_v6(char *buffer, const size_t current_len, const size_t max_len, int ifindex, struct in6_addr ip_address, int prefix_len) {
	struct {
		struct nlmsghdr nlh;
		struct ifaddrmsg ifa;
		char attrbuf[512];  // Larger buffer for IPv6 attribute
	} req;

	memset(&req, 0, sizeof(req));

	req.nlh.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifaddrmsg));
	req.nlh.nlmsg_type = RTM_NEWADDR;
	req.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_EXCL;
	req.nlh.nlmsg_seq = 0;
	req.nlh.nlmsg_pid = getpid();

	req.ifa.ifa_family = AF_INET6;
	req.ifa.ifa_prefixlen = prefix_len;
	req.ifa.ifa_flags = IFA_F_PERMANENT;
	req.ifa.ifa_index = ifindex;
	req.ifa.ifa_scope = RT_SCOPE_UNIVERSE;

	struct rtattr *rta = (struct rtattr *)(req.attrbuf);
	rta->rta_type = IFA_LOCAL;
	rta->rta_len = RTA_LENGTH(sizeof(struct in6_addr));
	memcpy(RTA_DATA(rta), &ip_address, sizeof(struct in6_addr));
	req.nlh.nlmsg_len += rta->rta_len;

	if (current_len + req.nlh.nlmsg_len > max_len) {
		return -1;
	}

	memcpy(buffer + current_len, &req, req.nlh.nlmsg_len);
	return current_len + req.nlh.nlmsg_len;
}

// Add IPv4 address removal request to buffer
size_t add_address_removal_request_v4(char *buffer, const size_t current_len, const size_t max_len, int ifindex, uint32_t ip_address, int prefix_len) {
	struct {
		struct nlmsghdr nlh;
		struct ifaddrmsg ifa;
	} req;

	memset(&req, 0, sizeof(req));

	req.nlh.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifaddrmsg));
	req.nlh.nlmsg_type = RTM_DELADDR;
	req.nlh.nlmsg_flags = NLM_F_REQUEST;
	req.nlh.nlmsg_seq = 0;
	req.nlh.nlmsg_pid = getpid();

	req.ifa.ifa_family = AF_INET;
	req.ifa.ifa_prefixlen = prefix_len;
	req.ifa.ifa_index = ifindex;
	req.ifa.ifa_scope = RT_SCOPE_UNIVERSE;

	if (current_len + req.nlh.nlmsg_len > max_len) {
		return -1;
	}

	memcpy(buffer + current_len, &req, req.nlh.nlmsg_len);
	return current_len + req.nlh.nlmsg_len;
}

// Add IPv6 address removal request to buffer
size_t add_address_removal_request_v6(char *buffer, const size_t current_len, const size_t max_len, int ifindex, struct in6_addr ip_address, int prefix_len) {
	struct {
		struct nlmsghdr nlh;
		struct ifaddrmsg ifa;
	} req;

	memset(&req, 0, sizeof(req));

	req.nlh.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifaddrmsg));
	req.nlh.nlmsg_type = RTM_DELADDR;
	req.nlh.nlmsg_flags = NLM_F_REQUEST;
	req.nlh.nlmsg_seq = 0;
	req.nlh.nlmsg_pid = getpid();

	req.ifa.ifa_family = AF_INET6;
	req.ifa.ifa_prefixlen = prefix_len;
	req.ifa.ifa_index = ifindex;
	req.ifa.ifa_scope = RT_SCOPE_UNIVERSE;

	if (current_len + req.nlh.nlmsg_len > max_len) {
		return -1;
	}

	memcpy(buffer + current_len, &req, req.nlh.nlmsg_len);
	return current_len + req.nlh.nlmsg_len;
}

int do_address_mod_message(int sock, char *buffer, int len) {
	struct sockaddr_nl nladdr = {
		.nl_family = AF_NETLINK
	};

	struct iovec iov = {
		.iov_base = buffer,
		.iov_len = len
	};

	struct msghdr msg = {
		.msg_name = &nladdr,
		.msg_namelen = sizeof(nladdr),
		.msg_iov = &iov,
		.msg_iovlen = 1
	};

	return sendmsg(sock, &msg, 0);
}

int get_address_mod_responses(int sock, void(^hndlr)(const struct nlmsghdr *)) {
	char buffer[8192]; // Define a buffer large enough for typical responses
	struct iovec iov = { buffer, sizeof(buffer) };
	struct sockaddr_nl nladdr;
	struct msghdr msg = {
		.msg_name = &nladdr,
		.msg_namelen = sizeof(nladdr),
		.msg_iov = &iov,
		.msg_iovlen = 1
	};

	int received = recvmsg(sock, &msg, 0); // Receive a message from the socket
	if (received < 0) {
		perror("Failed to receive response from kernel");
		return -1; // Return an error if receiving failed
	}

	// Loop through all the messages in the received buffer
	struct nlmsghdr *nh;
	for (nh = (struct nlmsghdr *)buffer; NLMSG_OK(nh, received); nh = NLMSG_NEXT(nh, received)) {
		if (nh->nlmsg_type == NLMSG_ERROR) {
			struct nlmsgerr *err = (struct nlmsgerr *)NLMSG_DATA(nh);
			if (err->error != 0) {
				fprintf(stderr, "Received error from kernel: %s\n", strerror(-err->error));
				return -1; // Return an error
			}
		} else if (nh->nlmsg_type == NLMSG_DONE) {
			break; // No more messages to process
		} else {
			hndlr(nh); // Call the handler function for each valid message
		}
	}

	return 0; // Return success
}

int get_address_dump_response(int sock, void(^hndlr)(const struct nlmsghdr *)) {
	struct sockaddr_nl nladdr;
	struct iovec iov;
	struct msghdr msg = {
		.msg_name = &nladdr,
		.msg_namelen = sizeof(nladdr),
		.msg_iov = &iov,
		.msg_iovlen = 1,
	};
	
	char *buf;
	int dump_intr = 0;
	
	int status = rtnl_recvmsg(sock, &msg, &buf);
	
	struct nlmsghdr *h = (struct nlmsghdr*)buf;
	int msglen = status;
	while (NLMSG_OK(h, msglen)) {
		if (h->nlmsg_flags & NLM_F_DUMP_INTR) {
			free(buf);
			return -1;
		}
		
		if (nladdr.nl_pid != 0) {
			continue;
		}
		
		if (h->nlmsg_type == NLMSG_ERROR) {
			free(buf);
			return -2;
		}
		
		hndlr(h);
		
		h = NLMSG_NEXT(h, msglen);
	}
	free(buf);
	return status;
}

int check_address_operation_response(int sock) {
	char buffer[4096];
	struct iovec iov = { buffer, sizeof(buffer) };
	struct sockaddr_nl sa;
	struct msghdr msg = { &sa, sizeof(sa), &iov, 1, NULL, 0, 0 };
	struct nlmsghdr *nh;

	int received = recvmsg(sock, &msg, 0);
	if (received < 0) {
		perror("Failed to receive response from kernel");
		return -1; // return an error if receiving failed
	}

	// check if the message is an error or an ACK
	for (nh = (struct nlmsghdr *)buffer; NLMSG_OK(nh, received); nh = NLMSG_NEXT(nh, received)) {
		if (nh->nlmsg_type == NLMSG_ERROR) {
			struct nlmsgerr *err = (struct nlmsgerr *)NLMSG_DATA(nh);
			if (err->error == 0) {
				printf("Operation succeeded.\n");
				return 0; // Success!
			} else {
				fprintf(stderr, "Error received: %s\n", strerror(-err->error));
				return err->error; // Return the error code from the kernel
			}
		} else if (nh->nlmsg_type == NLMSG_DONE) {
			printf("Operation finished.\n");
			return 0; // Success
		}
	}

	return 0; // If we reach here, the operation was successful
}


int read_address(const struct nlmsghdr *nl_header_answer, void(^hndlr)(struct ifaddrmsg *ifa, struct rtattr *attrs[RTA_MAX+1])) {
	struct ifaddrmsg *ifa = NLMSG_DATA(nl_header_answer);
	int len = nl_header_answer->nlmsg_len;
	struct rtattr *tb[IFA_MAX+1];
	char buf[256];
	len -= NLMSG_LENGTH(sizeof(*ifa));
	if (len < 0) {
		return -1;
	}
	
	parse_rtattr(tb, IFA_MAX, IFA_RTA(ifa), len);
	
	hndlr(ifa, tb);
	return 0;
}

void get_attribute_data_ifa(unsigned char family, struct rtattr *attrs[IFA_MAX+1], int attrKey, char **buf) {
	if (attrs[attrKey]) {
		char *newBuff = malloc(256);
		inet_ntop(family, RTA_DATA(attrs[attrKey]), newBuff, 256);
		(*buf) = newBuff;
	} else {
		*buf = NULL;
	}
}

int open_netlink()
{
	struct sockaddr_nl saddr;

	int sock = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);

	if (sock < 0) {
		perror("Failed to open netlink socket");
		return -1;
	}

	memset(&saddr, 0, sizeof(saddr));

	saddr.nl_family = AF_NETLINK;
	saddr.nl_pid = getpid();

	if (bind(sock, (struct sockaddr *)&saddr, sizeof(saddr)) < 0) {
		perror("Failed to bind to netlink socket");
		close(sock);
		return -1;
	}

	return sock;
}

int do_route_dump_request_v4(int sock)
{
	struct {
		struct nlmsghdr nlh;
		struct rtmsg rtm;
	} nl_request;

	nl_request.nlh.nlmsg_type = RTM_GETROUTE;
	nl_request.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
	nl_request.nlh.nlmsg_len = sizeof(nl_request);
	nl_request.nlh.nlmsg_seq = time(NULL);
	nl_request.rtm.rtm_family = AF_INET;

	return send(sock, &nl_request, sizeof(nl_request), 0);
}

int do_route_dump_request_v6(int sock)
{
	struct {
		struct nlmsghdr nlh;
		struct rtmsg rtm;
	} nl_request;

	nl_request.nlh.nlmsg_type = RTM_GETROUTE;
	nl_request.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
	nl_request.nlh.nlmsg_len = sizeof(nl_request);
	nl_request.nlh.nlmsg_seq = time(NULL);
	nl_request.rtm.rtm_family = AF_INET6;

	return send(sock, &nl_request, sizeof(nl_request), 0);
}


int get_route_dump_response(int sock, void(^hndlr)(struct nlmsghdr*))
{
	struct sockaddr_nl nladdr;
	struct iovec iov;
	struct msghdr msg = {
		.msg_name = &nladdr,
		.msg_namelen = sizeof(nladdr),
		.msg_iov = &iov,
		.msg_iovlen = 1,
	};

	char *buf;
	int dump_intr = 0;

	int status = rtnl_recvmsg(sock, &msg, &buf);

	struct nlmsghdr *h = (struct nlmsghdr *)buf;
	int msglen = status;
	while (NLMSG_OK(h, msglen)) {
		if (h->nlmsg_flags & NLM_F_DUMP_INTR) {
			free(buf);
			return -1;
		}

		if (nladdr.nl_pid != 0) {
			continue;
		}

		if (h->nlmsg_type == NLMSG_ERROR) {
			perror("netlink reported error");
			free(buf);
		}

		hndlr(h);

		h = NLMSG_NEXT(h, msglen);
	}

	free(buf);

	return status;
}

int read_route(const struct nlmsghdr *nl_header_answer, void(^hndlr)(struct rtmsg *r, struct rtattr *tb[RTA_MAX+1])) {
	struct rtmsg* r = NLMSG_DATA(nl_header_answer);
	int len = nl_header_answer->nlmsg_len;
	struct rtattr* tb[RTA_MAX+1];
	char buf[256];

	len -= NLMSG_LENGTH(sizeof(*r));
	
	if (len < 0) {
		return -1;
	}

	parse_rtattr(tb, RTA_MAX, RTM_RTA(r), len);
	
	hndlr(r, tb);
	return 0;
}

void get_attribute_data_rt(unsigned char family, struct rtattr *attrs[RTA_MAX+1], enum rtattr_type_t attrKey, char **buf) {
	if (attrs[attrKey]) {
		char *newBuff = malloc(256);
		inet_ntop(family, RTA_DATA(attrs[attrKey]), newBuff, 256);
		(*buf) = newBuff;
	} else {
		*buf = NULL;
	}
}

int get_attribute_uint32_rt(struct rtattr* attrs[RTA_MAX+1], enum rtattr_type_t attrKey, uint32_t *num) {
	if (attrs[attrKey]) {
		int ifidx = *(uint32_t*)RTA_DATA(attrs[attrKey]);
		(*num) = ifidx;
		return 0;
	} else {
		(*num) = 0;
		return -1;
	}
}
