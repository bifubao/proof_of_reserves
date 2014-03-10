//
//  main.cpp
//
//  Created by panzhibiao@bifubao.com on 2014-03-09.
//  Copyright (c) 2014 Bifubao.com Inc. All rights reserved.
//
//  build: g++ main.cpp -lcrypto -L/usr/local/lib -I/usr/local/include -o build_tree
//
//
#include <algorithm>
#include <iostream>
#include <fstream>
#include <vector>
#include <string>

#include <assert.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include <openssl/sha.h>


typedef struct Node_ {
  long long         sum;
  unsigned char hash[8];
  
  bool operator < (const struct Node_ &right) const {
    return memcmp(this->hash, right.hash, 8) < 0 ? true : false;
  }
} Node;

typedef std::vector<Node> Nodes;

struct Summary {
  long long         sum;
  long long padding_sum;
  size_t     user_count;
  int             level;
};


// make_parent_node
void make_parent_node(const Node *l, const Node *r, Node *p) {
  unsigned char hash[SHA256_DIGEST_LENGTH];
    unsigned char buf[24]= {0};
  
  p->sum = l->sum + r->sum;
  memcpy(buf,    (unsigned char *)&(p->sum),  8);
  memcpy(buf+8,  (unsigned char *)l->hash, 8);
  memcpy(buf+16, (unsigned char *)r->hash, 8);
  SHA256(buf, 24, hash);
  memcpy(p->hash, hash, 8);
}

// make_user_node
void make_user_node(const char *uid, long long balance, Node *node) {
  unsigned char hash[SHA256_DIGEST_LENGTH];
  char buf[17] = {0};
  node->sum = balance;
  sprintf(buf, "%016lld", balance);

  SHA256_CTX sha256;
  SHA256_Init(&sha256);
  SHA256_Update(&sha256, uid, strlen(uid));
  SHA256_Update(&sha256, buf, 16);
  SHA256_Final(hash, &sha256);
  
  memcpy(node->hash, hash, 8);
}

// build_parent_nodes
void build_parent_nodes(Nodes *nodes, Nodes *parents) {
  Node pnode;
  assert(nodes->size()%2 == 0);
  for (Nodes::iterator it = nodes->begin(); it != nodes->end(); it += 2) {
    make_parent_node(&*it, &*(it+1), &pnode);
    parents->push_back(pnode);
  }
}

// dump_hex
void dump_hex(unsigned char *buf, size_t len) {
  for (size_t i = 0; i < len; i++) {
    printf("%02x", buf[i]);
  }
}





/*********************************** main ************************************/

int main(int argc, char **argv)
{
  char *file_input = NULL;
  int c;
  
  Node node;
  Nodes nodes;
  struct Summary summary;
  memset(&summary, 0, sizeof(struct Summary));
  
  // options
  while ((c = getopt(argc, argv, "i:")) != -1) {
    switch (c) {
      case 'i':
        file_input = optarg;
        break;
      default:
        break;
    }
  }
  
  if (!file_input) {
    printf("Usage: ./build_tree -i inputs.txt\n");
    exit(EXIT_SUCCESS);
  }
  
  // read input file
  std::ifstream fin(file_input);
  if (!fin.is_open()) {
    std::cerr << "open file failure: " << file_input << std::endl;
    exit(EXIT_FAILURE);
  }
  while (!fin.eof()) {
    std::string uid;
    std::string balance;
    if (!std::getline(fin, uid, '\t') || !std::getline(fin, balance, '\n')) {
      break;
    }
    make_user_node(uid.c_str(), atoll(balance.c_str()), &node);
    nodes.push_back(node);
    summary.sum += node.sum;
  }
  fin.close();
  summary.user_count = nodes.size();
  
  // nodes at level 0 should be sorted
  std::sort(nodes.begin(), nodes.end());
  
  int idx = 0;
  Nodes parents;
  parents.reserve(nodes.size()%2 + 1);
  while (nodes.size() > 1) {
    if (nodes.size() % 2 == 1) {
      summary.padding_sum += nodes[nodes.size()-1].sum;
      nodes.push_back(nodes[nodes.size()-1]);
    }
    
    for (Nodes::iterator it = nodes.begin(); it != nodes.end(); it++) {
      std::cout << idx++ << "\t" << summary.level << "\t" << it->sum << "\t";
      dump_hex(it->hash, 8);
      std::cout << std::endl;
    }
    parents.resize(0);
    build_parent_nodes(&nodes, &parents);
    nodes = parents;
    summary.level++;
  }
  std::cout << idx++ << "\t" << summary.level << "\t" << nodes[0].sum << "\t";
  dump_hex(nodes[0].hash, 8);
  std::cout << std::endl;
  
  std::cout << summary.user_count << "\t" << summary.sum << "\t"
    << summary.padding_sum << "\t" << summary.level << std::endl;
  
  return 0;
}

