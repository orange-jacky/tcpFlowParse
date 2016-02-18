#include "tcpFlowParse.h"


//带头结点的单链表
/* 单链表的基本操作(9个) */
int InitList(LinkList *list){

  *list = (LinkList)malloc(sizeof(LNode));
  if(*list == NULL)
      return -1;

   memset(*list, 0x00, sizeof(LNode) ); 
   (*list)->next = NULL;
   
   return 0; 

}

void DestroyList(LinkList *list){

  LinkList p;
  while(*list){
      p = *list;
      *list = (*list)->next;
      free(p);
  }

  return ;
}

void ClearList(LinkList *list){

    LinkList p,q;
    p = (*list)->next;
    (*list)->next = NULL;
    while(p){
      q = p;
      p = p->next;
      free(q);
    }
    return ;
}

//0 非空    -1 空
Status ListEmpty(LinkList list){
  if(list->next)
    return 0;
  return -1;
}

int ListLength(LinkList list){
  int i = 0 ;
  LinkList p;
  p = list->next;
  while(p){
    i++;
    p = p->next;
  }
  return i;

}

int ListInsert(LinkList *list,LElemType *e){

    LinkList p = NULL, newNode = NULL;
    p = (*list);
    while(p->next){
      p = p->next;
    }
   
    newNode = (LinkList)malloc(sizeof(LNode));
    if(newNode == NULL)
        return -1;

    //链表尾部插入
    memcpy(&(newNode->data), e, sizeof(LElemType));
    newNode->next = NULL;



    p->next = newNode;

    return 0;

}

Status ListDel(LinkList *list,LinkList p){

    LinkList pre, next, q;

    q = (*list)->next;
    while(q){
      if(q->next == p){

        next = p->next;
        pre = q;
        pre->next = next;
        free(p);

      }
      else{
        q = q->next;
      }
    };

    return -1;
}


void ListTraverse(LinkList list,void(*vi)(LElemType)){


  return ;
}

LinkList ListFind(LinkList list, LElemType *e){
  LinkList p;
  p = list->next;
  while(p){
    if(memcmp(p->data.cupInfo.masterfields.PAN, e->cupInfo.masterfields.PAN, sizeof(e->cupInfo.masterfields.PAN)) == 0)
    {
      return p;
    }else{
      p = p->next;
    }
  }

  return NULL;
}
