// SPDX-License-Identifier: GPL-2.0-only
/*
 * Landlock tests - CAN (Controller Area Network)
 *
 * Copyright © 2026 Landlock Contributors
 */

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/landlock.h>
#include <linux/can.h>
#include <linux/can/raw.h>
#include <linux/can/error.h>
#include <net/if.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "common.h"

/* CAN interface names for testing */
static const char can_if0[] = "vcan0";
static const char can_if1[] = "vcan1";
static const char can_if2[] = "vcan2";

enum can_sandbox_type {
	NO_CAN_SANDBOX,
	CAN_SANDBOX_RAW, /* Deny CAN_RAW access */
	CAN_SANDBOX_BCM, /* Deny CAN_BCM access */
	CAN_SANDBOX_ALL, /* Deny all CAN access */
};

struct can_fixture {
	const char *ifname;
	unsigned int ifindex;
};

static int create_vcan_interface(const char *ifname)
{
	char cmd[512];
	int ret;

	/* Try to load vcan module first - ignore errors as it might be built-in */
	system("modprobe vcan 2>/dev/null");

	/* Create vcan interface with verbose output for debugging */
	snprintf(cmd, sizeof(cmd), "ip link add name %s type vcan", ifname);
	ret = system(cmd);
	if (ret != 0) {
		fprintf(stderr,
			"Failed to create vcan interface '%s': command='%s' ret=%d\n",
			ifname, cmd, ret);
		return -1;
	}

	/* Bring interface up */
	snprintf(cmd, sizeof(cmd), "ip link set dev %s up", ifname);
	ret = system(cmd);
	if (ret != 0) {
		fprintf(stderr,
			"Failed to bring up vcan interface '%s': command='%s' ret=%d\n",
			ifname, cmd, ret);
		/* Clean up the interface we just created */
		snprintf(cmd, sizeof(cmd), "ip link delete %s 2>/dev/null",
			 ifname);
		system(cmd);
		return -1;
	}

	return 0;
}

static void destroy_vcan_interface(const char *ifname)
{
	char cmd[256];

	/* Bring interface down */
	snprintf(cmd, sizeof(cmd), "ip link set dev %s down 2>/dev/null",
		 ifname);
	system(cmd);

	/* Delete interface */
	snprintf(cmd, sizeof(cmd), "ip link delete %s 2>/dev/null", ifname);
	system(cmd);
}

static int get_can_ifindex(const char *ifname)
{
	struct ifreq ifr;
	int sock_fd;

	sock_fd = socket(AF_CAN, SOCK_RAW, CAN_RAW);
	if (sock_fd < 0)
		return -errno;

	strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);
	ifr.ifr_name[IFNAMSIZ - 1] = '\0';

	if (ioctl(sock_fd, SIOCGIFINDEX, &ifr) < 0) {
		close(sock_fd);
		return -errno;
	}

	close(sock_fd);
	return ifr.ifr_ifindex;
}

static int create_can_socket(void)
{
	int sock_fd;

	sock_fd = socket(AF_CAN, SOCK_RAW | SOCK_CLOEXEC, CAN_RAW);
	if (sock_fd < 0)
		return -errno;

	return sock_fd;
}

static int bind_can_socket(int sock_fd, unsigned int ifindex)
{
	struct sockaddr_can addr;

	memset(&addr, 0, sizeof(addr));
	addr.can_family = AF_CAN;
	addr.can_ifindex = ifindex;

	if (bind(sock_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0)
		return -errno;

	return 0;
}

static int send_can_frame(int sock_fd, canid_t can_id, const uint8_t *data,
			  uint8_t dlc)
{
	struct can_frame frame;

	memset(&frame, 0, sizeof(frame));
	frame.can_id = can_id;
	frame.can_dlc = dlc;
	if (data && dlc > 0)
		memcpy(frame.data, data, dlc);

	if (write(sock_fd, &frame, sizeof(frame)) != sizeof(frame))
		return -errno;

	return 0;
}

static int recv_can_frame(int sock_fd, struct can_frame *frame, int timeout_ms)
{
	fd_set readfds;
	struct timeval timeout;
	int ret;

	FD_ZERO(&readfds);
	FD_SET(sock_fd, &readfds);

	timeout.tv_sec = timeout_ms / 1000;
	timeout.tv_usec = (timeout_ms % 1000) * 1000;

	ret = select(sock_fd + 1, &readfds, NULL, NULL, &timeout);
	if (ret < 0)
		return -errno;
	if (ret == 0)
		return -ETIMEDOUT;

	ret = read(sock_fd, frame, sizeof(*frame));
	if (ret != sizeof(*frame))
		return -EIO;

	return 0;
}

FIXTURE(can_basic)
{
	struct can_fixture if0, if1, if2;
};

FIXTURE_VARIANT(can_basic)
{
	const enum can_sandbox_type sandbox;
};

FIXTURE_SETUP(can_basic)
{
	int ifindex;
	int ruleset_fd;
	struct landlock_ruleset_attr ruleset_attr = {
		.handled_access_net = LANDLOCK_ACCESS_NET_BIND_TCP |
				      LANDLOCK_ACCESS_NET_CONNECT_TCP |
				      LANDLOCK_ACCESS_NET_BIND_CAN_RAW |
				      LANDLOCK_ACCESS_NET_CONNECT_CAN_BCM,
	};

	disable_caps(_metadata);

	/* Create new network namespace */
	set_cap(_metadata, CAP_SYS_ADMIN);
	ASSERT_EQ(0, unshare(CLONE_NEWNET));
	clear_cap(_metadata, CAP_SYS_ADMIN);

	/* Create vcan interfaces (needs CAP_NET_ADMIN) */
	set_ambient_cap(_metadata, CAP_NET_ADMIN);
	ASSERT_EQ(0, create_vcan_interface(can_if0))
	{
		TH_LOG("Failed to create %s", can_if0);
	}
	ASSERT_EQ(0, create_vcan_interface(can_if1))
	{
		TH_LOG("Failed to create %s", can_if1);
	}
	ASSERT_EQ(0, create_vcan_interface(can_if2))
	{
		TH_LOG("Failed to create %s", can_if2);
	}
	clear_ambient_cap(_metadata, CAP_NET_ADMIN);

	/* Get interface indices */
	ifindex = get_can_ifindex(can_if0);
	ASSERT_GT(ifindex, 0)
	{
		TH_LOG("Failed to get ifindex for %s: %s", can_if0,
		       strerror(-ifindex));
	}
	self->if0.ifname = can_if0;
	self->if0.ifindex = ifindex;

	ifindex = get_can_ifindex(can_if1);
	ASSERT_GT(ifindex, 0);
	self->if1.ifname = can_if1;
	self->if1.ifindex = ifindex;

	ifindex = get_can_ifindex(can_if2);
	ASSERT_GT(ifindex, 0);
	self->if2.ifname = can_if2;
	self->if2.ifindex = ifindex;

	/* Apply Landlock sandbox if needed */
	if (variant->sandbox != NO_CAN_SANDBOX) {
		ruleset_fd = landlock_create_ruleset(&ruleset_attr,
						     sizeof(ruleset_attr), 0);
		ASSERT_LE(0, ruleset_fd)
		{
			TH_LOG("Failed to create ruleset: %s", strerror(errno));
		}

		/* Add rules to allow specific access based on sandbox type */
		if (variant->sandbox == CAN_SANDBOX_RAW) {
			/* Allow BCM on all interfaces, deny RAW */
			struct landlock_net_port_attr net_port;

			net_port.allowed_access =
				LANDLOCK_ACCESS_NET_CONNECT_CAN_BCM;
			/* Add rule for each interface - port=ifindex for CAN */
			net_port.port = self->if0.ifindex;
			ASSERT_EQ(0, landlock_add_rule(ruleset_fd,
						       LANDLOCK_RULE_NET_PORT,
						       &net_port, 0));
			net_port.port = self->if1.ifindex;
			ASSERT_EQ(0, landlock_add_rule(ruleset_fd,
						       LANDLOCK_RULE_NET_PORT,
						       &net_port, 0));
			net_port.port = self->if2.ifindex;
			ASSERT_EQ(0, landlock_add_rule(ruleset_fd,
						       LANDLOCK_RULE_NET_PORT,
						       &net_port, 0));
		} else if (variant->sandbox == CAN_SANDBOX_BCM) {
			/* Allow RAW on all interfaces, deny BCM */
			struct landlock_net_port_attr net_port;

			net_port.allowed_access =
				LANDLOCK_ACCESS_NET_BIND_CAN_RAW;
			/* Add rule for each interface - port=ifindex for CAN */
			net_port.port = self->if0.ifindex;
			ASSERT_EQ(0, landlock_add_rule(ruleset_fd,
						       LANDLOCK_RULE_NET_PORT,
						       &net_port, 0));
			net_port.port = self->if1.ifindex;
			ASSERT_EQ(0, landlock_add_rule(ruleset_fd,
						       LANDLOCK_RULE_NET_PORT,
						       &net_port, 0));
			net_port.port = self->if2.ifindex;
			ASSERT_EQ(0, landlock_add_rule(ruleset_fd,
						       LANDLOCK_RULE_NET_PORT,
						       &net_port, 0));
		} else if (variant->sandbox == CAN_SANDBOX_ALL) {
			/* Deny both - no rules needed, just restrict */
		}

		/* Enforce the ruleset */
		ASSERT_EQ(0, prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0));
		ASSERT_EQ(0, landlock_restrict_self(ruleset_fd, 0))
		{
			TH_LOG("Failed to enforce ruleset: %s",
			       strerror(errno));
		}

		EXPECT_EQ(0, close(ruleset_fd));
	}
}

FIXTURE_TEARDOWN(can_basic)
{
	/* Clean up vcan interfaces */
	destroy_vcan_interface(can_if0);
	destroy_vcan_interface(can_if1);
	destroy_vcan_interface(can_if2);
}

/* clang-format off */
FIXTURE_VARIANT_ADD(can_basic, no_sandbox) {
	/* clang-format on */
	.sandbox = NO_CAN_SANDBOX,
};

/* clang-format off */
FIXTURE_VARIANT_ADD(can_basic, sandbox_raw) {
	/* clang-format on */
	.sandbox = CAN_SANDBOX_RAW,
};

/* clang-format off */
FIXTURE_VARIANT_ADD(can_basic, sandbox_bcm) {
	/* clang-format on */
	.sandbox = CAN_SANDBOX_BCM,
};

/* clang-format off */
FIXTURE_VARIANT_ADD(can_basic, sandbox_all) {
	/* clang-format on */
	.sandbox = CAN_SANDBOX_ALL,
};

TEST_F(can_basic, create_and_bind)
{
	int sock_fd;
	int ret;

	/* Create CAN socket - creation always succeeds */
	sock_fd = create_can_socket();
	ASSERT_GE(sock_fd, 0)
	{
		TH_LOG("Failed to create CAN socket: %s", strerror(-sock_fd));
	}

	/* Bind to first interface - this is where Landlock enforcement happens */
	ret = bind_can_socket(sock_fd, self->if0.ifindex);
	if (variant->sandbox == CAN_SANDBOX_RAW ||
	    variant->sandbox == CAN_SANDBOX_ALL) {
		/* In a RAW-restricted sandbox, bind should fail */
		EXPECT_EQ(-EACCES, ret)
		{
			TH_LOG("Expected EACCES for CAN_RAW bind in sandbox, got: %s",
			       strerror(-ret));
		}
	} else {
		/* Should succeed when not restricted */
		EXPECT_EQ(0, ret)
		{
			TH_LOG("Failed to bind CAN socket to %s: %s",
			       self->if0.ifname, strerror(-ret));
		}
	}

	EXPECT_EQ(0, close(sock_fd));
}

TEST_F(can_basic, send_frame)
{
	int sock_fd;
	int ret;
	uint8_t data[8] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };

	/* Socket creation always succeeds */
	sock_fd = create_can_socket();
	ASSERT_GE(sock_fd, 0);

	/* Bind - this is where enforcement happens */
	ret = bind_can_socket(sock_fd, self->if0.ifindex);
	if (variant->sandbox == CAN_SANDBOX_RAW ||
	    variant->sandbox == CAN_SANDBOX_ALL) {
		/* Bind should fail in RAW-restricted sandbox */
		EXPECT_EQ(-EACCES, ret);
		if (ret < 0) {
			close(sock_fd);
			return; /* Test passes - bind was blocked */
		}
	} else {
		ASSERT_EQ(0, ret);
	}

	/* Try to send a frame - should work if bind succeeded */
	ret = send_can_frame(sock_fd, 0x123, data, 8);
	EXPECT_EQ(0, ret)
	{
		TH_LOG("Failed to send CAN frame: %s", strerror(-ret));
	}

	EXPECT_EQ(0, close(sock_fd));
}

TEST_F(can_basic, recv_frame)
{
	int send_fd, recv_fd;
	int status;
	int ret;
	struct can_frame frame;
	uint8_t data[8] = { 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11 };
	pid_t child;

	/* Create sender socket - always succeeds */
	send_fd = create_can_socket();
	ASSERT_GE(send_fd, 0);

	/* Bind sender socket - this is where enforcement happens */
	ret = bind_can_socket(send_fd, self->if0.ifindex);
	if (variant->sandbox == CAN_SANDBOX_RAW ||
	    variant->sandbox == CAN_SANDBOX_ALL) {
		/* Bind should fail in RAW-restricted sandbox */
		EXPECT_EQ(-EACCES, ret);
		if (ret < 0) {
			close(send_fd);
			return; /* Test passes - bind was blocked */
		}
	}
	if (ret != 0) {
		close(send_fd);
		SKIP(return, "Cannot bind sender socket");
	}

	/* Create receiver socket */
	recv_fd = create_can_socket();
	ASSERT_GE(recv_fd, 0);

	ret = bind_can_socket(recv_fd, self->if0.ifindex);
	if (ret != 0) {
		close(send_fd);
		close(recv_fd);
		SKIP(return, "Cannot bind receiver socket");
	}

	/* Fork to send frame from child process */
	child = fork();
	ASSERT_LE(0, child);

	if (child == 0) {
		/* Child: send frame */
		close(recv_fd);
		usleep(50000); /* Wait 50ms for parent to be ready */

		ret = send_can_frame(send_fd, 0x456, data, 8);
		close(send_fd);
		if (ret != 0)
			_exit(EXIT_FAILURE);
		_exit(EXIT_SUCCESS);
	}

	/* Parent: receive frame */
	close(send_fd);

	ret = recv_can_frame(recv_fd, &frame, 1000);
	EXPECT_EQ(0, ret)
	{
		TH_LOG("Failed to receive CAN frame: %s", strerror(-ret));
	}

	if (ret == 0) {
		EXPECT_EQ(0x456U, frame.can_id);
		EXPECT_EQ(8, frame.can_dlc);
		EXPECT_EQ(0, memcmp(frame.data, data, 8));
	}

	close(recv_fd);

	/* Wait for child */
	EXPECT_EQ(child, waitpid(child, &status, 0));
	EXPECT_EQ(1, WIFEXITED(status));
}

TEST_F(can_basic, multiple_interfaces)
{
	int sock_fd0, sock_fd1, sock_fd2;
	int ret;

	/* Create and bind to all three interfaces */
	sock_fd0 = create_can_socket();
	ASSERT_GE(sock_fd0, 0);
	ret = bind_can_socket(sock_fd0, self->if0.ifindex);
	EXPECT_TRUE(ret == 0 || ret == -EACCES);

	sock_fd1 = create_can_socket();
	ASSERT_GE(sock_fd1, 0);
	ret = bind_can_socket(sock_fd1, self->if1.ifindex);
	EXPECT_TRUE(ret == 0 || ret == -EACCES);

	sock_fd2 = create_can_socket();
	ASSERT_GE(sock_fd2, 0);
	ret = bind_can_socket(sock_fd2, self->if2.ifindex);
	EXPECT_TRUE(ret == 0 || ret == -EACCES);

	EXPECT_EQ(0, close(sock_fd0));
	EXPECT_EQ(0, close(sock_fd1));
	EXPECT_EQ(0, close(sock_fd2));
}

/* clang-format off */
FIXTURE(can_filter) {};
/* clang-format on */

FIXTURE_SETUP(can_filter)
{
	disable_caps(_metadata);

	/* Create new network namespace */
	set_cap(_metadata, CAP_SYS_ADMIN);
	ASSERT_EQ(0, unshare(CLONE_NEWNET));
	clear_cap(_metadata, CAP_SYS_ADMIN);

	/* Create vcan interface */
	set_ambient_cap(_metadata, CAP_NET_ADMIN);
	ASSERT_EQ(0, create_vcan_interface(can_if0))
	{
		TH_LOG("Failed to create %s", can_if0);
	}
	clear_ambient_cap(_metadata, CAP_NET_ADMIN);
}

FIXTURE_TEARDOWN(can_filter)
{
	destroy_vcan_interface(can_if0);
}

TEST_F(can_filter, set_can_filter)
{
	int sock_fd;
	int ret;
	struct can_filter filter[2];
	unsigned int ifindex;

	ifindex = get_can_ifindex(can_if0);
	ASSERT_GT(ifindex, 0);

	sock_fd = create_can_socket();
	ASSERT_GE(sock_fd, 0);

	ret = bind_can_socket(sock_fd, ifindex);
	ASSERT_EQ(0, ret);

	/* Set CAN filter for specific IDs */
	filter[0].can_id = 0x123;
	filter[0].can_mask = CAN_SFF_MASK;
	filter[1].can_id = 0x456;
	filter[1].can_mask = CAN_SFF_MASK;

	ret = setsockopt(sock_fd, SOL_CAN_RAW, CAN_RAW_FILTER, &filter,
			 sizeof(filter));
	EXPECT_EQ(0, ret)
	{
		TH_LOG("Failed to set CAN filter: %s", strerror(errno));
	}

	EXPECT_EQ(0, close(sock_fd));
}

TEST_F(can_filter, error_filter)
{
	int sock_fd;
	int ret;
	can_err_mask_t err_mask = CAN_ERR_TX_TIMEOUT | CAN_ERR_BUSOFF;
	unsigned int ifindex;

	ifindex = get_can_ifindex(can_if0);
	ASSERT_GT(ifindex, 0);

	sock_fd = create_can_socket();
	ASSERT_GE(sock_fd, 0);

	ret = bind_can_socket(sock_fd, ifindex);
	ASSERT_EQ(0, ret);

	/* Set error mask */
	ret = setsockopt(sock_fd, SOL_CAN_RAW, CAN_RAW_ERR_FILTER, &err_mask,
			 sizeof(err_mask));
	EXPECT_EQ(0, ret)
	{
		TH_LOG("Failed to set CAN error filter: %s", strerror(errno));
	}

	EXPECT_EQ(0, close(sock_fd));
}

/* clang-format off */
FIXTURE(can_mini) {};
/* clang-format on */

FIXTURE_SETUP(can_mini)
{
	disable_caps(_metadata);

	/* Create new network namespace */
	set_cap(_metadata, CAP_SYS_ADMIN);
	ASSERT_EQ(0, unshare(CLONE_NEWNET));
	clear_cap(_metadata, CAP_SYS_ADMIN);

	/* Create vcan interface */
	set_ambient_cap(_metadata, CAP_NET_ADMIN);
	ASSERT_EQ(0, create_vcan_interface(can_if0))
	{
		TH_LOG("Failed to create %s", can_if0);
	}
	clear_ambient_cap(_metadata, CAP_NET_ADMIN);
}

FIXTURE_TEARDOWN(can_mini)
{
	destroy_vcan_interface(can_if0);
}

/*
 * Test placeholder for future CAN access rights.
 * Currently, Landlock doesn't define CAN-specific access rights yet.
 * This test validates that the basic CAN infrastructure works.
 */
TEST_F(can_mini, basic_socket_operations)
{
	int sock_fd;
	unsigned int ifindex;

	ifindex = get_can_ifindex(can_if0);
	ASSERT_GT(ifindex, 0)
	{
		TH_LOG("Failed to get ifindex for %s", can_if0);
	}

	sock_fd = create_can_socket();
	ASSERT_GE(sock_fd, 0)
	{
		TH_LOG("Failed to create CAN socket");
	}

	EXPECT_EQ(0, bind_can_socket(sock_fd, ifindex))
	{
		TH_LOG("Failed to bind CAN socket");
	}

	EXPECT_EQ(0, close(sock_fd));
}

TEST_F(can_mini, loopback_test)
{
	int sock_fd;
	int ret;
	int loopback = 1;
	int recv_own_msgs = 1;
	unsigned int ifindex;

	ifindex = get_can_ifindex(can_if0);
	ASSERT_GT(ifindex, 0);

	sock_fd = create_can_socket();
	ASSERT_GE(sock_fd, 0);

	/* Enable loopback and receiving own messages */
	ret = setsockopt(sock_fd, SOL_CAN_RAW, CAN_RAW_LOOPBACK, &loopback,
			 sizeof(loopback));
	EXPECT_EQ(0, ret);

	ret = setsockopt(sock_fd, SOL_CAN_RAW, CAN_RAW_RECV_OWN_MSGS,
			 &recv_own_msgs, sizeof(recv_own_msgs));
	EXPECT_EQ(0, ret);

	ret = bind_can_socket(sock_fd, ifindex);
	EXPECT_EQ(0, ret);

	/* Send and receive on same socket */
	uint8_t data[8] = { 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88 };

	ret = send_can_frame(sock_fd, 0x789, data, 8);
	EXPECT_EQ(0, ret);

	struct can_frame frame;

	ret = recv_can_frame(sock_fd, &frame, 1000);
	EXPECT_EQ(0, ret);

	if (ret == 0) {
		EXPECT_EQ(0x789U, frame.can_id);
		EXPECT_EQ(8, frame.can_dlc);
		EXPECT_EQ(0, memcmp(frame.data, data, 8));
	}

	EXPECT_EQ(0, close(sock_fd));
}

TEST_HARNESS_MAIN
