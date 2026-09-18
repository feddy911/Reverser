// samples/NestWalk.cpp
// Handmade BST + linked stack/queue. Recursion for tree ops; no STL containers.
#include <iostream>

struct Node {
    int key;
    Node* left;
    Node* right;
};

struct Link {
    Node* node;
    Link* next;
};

struct Stack {
    Link* top;
};

struct Queue {
    Link* head;
    Link* tail;
};

static Node* node_new(int key) {
    Node* n = new Node;
    n->key = key;
    n->left = 0;
    n->right = 0;
    return n;
}

static Link* link_new(Node* node) {
    Link* p = new Link;
    p->node = node;
    p->next = 0;
    return p;
}

static Node* tree_insert(Node* t, int key) {
    if (t == 0) {
        return node_new(key);
    }
    if (key < t->key) {
        t->left = tree_insert(t->left, key);
    } else if (key > t->key) {
        t->right = tree_insert(t->right, key);
    }
    return t;
}

static int tree_height(const Node* t) {
    if (t == 0) {
        return 0;
    }
    const int lh = tree_height(t->left);
    const int rh = tree_height(t->right);
    return 1 + (lh > rh ? lh : rh);
}

static int tree_sum(const Node* t) {
    if (t == 0) {
        return 0;
    }
    return t->key + tree_sum(t->left) + tree_sum(t->right);
}

static int tree_max(const Node* t) {
    if (t == 0) {
        return 0;
    }
    if (t->right == 0) {
        return t->key;
    }
    return tree_max(t->right);
}

static void tree_inorder(const Node* t) {
    if (t == 0) {
        return;
    }
    tree_inorder(t->left);
    std::cout << ' ' << t->key;
    tree_inorder(t->right);
}

static void tree_free(Node* t) {
    if (t == 0) {
        return;
    }
    tree_free(t->left);
    tree_free(t->right);
    delete t;
}

static void stack_push(Stack* s, Node* node) {
    Link* p = link_new(node);
    p->next = s->top;
    s->top = p;
}

static Node* stack_pop(Stack* s) {
    Link* p = s->top;
    Node* n = p->node;
    s->top = p->next;
    delete p;
    return n;
}

static void queue_push(Queue* q, Node* node) {
    Link* p = link_new(node);
    if (q->tail == 0) {
        q->head = p;
        q->tail = p;
        return;
    }
    q->tail->next = p;
    q->tail = p;
}

static Node* queue_pop(Queue* q) {
    Link* p = q->head;
    Node* n = p->node;
    q->head = p->next;
    if (q->head == 0) {
        q->tail = 0;
    }
    delete p;
    return n;
}

static void tree_dfs(Node* root) {
    Stack s;
    s.top = 0;
    if (root == 0) {
        return;
    }
    stack_push(&s, root);
    while (s.top != 0) {
        Node* n = stack_pop(&s);
        std::cout << ' ' << n->key;
        if (n->right != 0) {
            stack_push(&s, n->right);
        }
        if (n->left != 0) {
            stack_push(&s, n->left);
        }
    }
}

static void tree_bfs(Node* root) {
    Queue q;
    q.head = 0;
    q.tail = 0;
    if (root == 0) {
        return;
    }
    queue_push(&q, root);
    while (q.head != 0) {
        Node* n = queue_pop(&q);
        std::cout << ' ' << n->key;
        if (n->left != 0) {
            queue_push(&q, n->left);
        }
        if (n->right != 0) {
            queue_push(&q, n->right);
        }
    }
}

int main() {
    const int keys[] = {8, 3, 10, 1, 6, 14, 4, 7};
    Node* root = 0;
    for (int i = 0; i < 8; ++i) {
        root = tree_insert(root, keys[i]);
    }

    std::cout << "=== NestWalk ===\n";
    std::cout << "height=" << tree_height(root) << "\n";
    std::cout << "sum=" << tree_sum(root) << "\n";
    std::cout << "max=" << tree_max(root) << "\n";
    std::cout << "inorder:";
    tree_inorder(root);
    std::cout << "\n";
    std::cout << "bfs:";
    tree_bfs(root);
    std::cout << "\n";
    std::cout << "dfs:";
    tree_dfs(root);
    std::cout << "\n";

    tree_free(root);
    return 0;
}
