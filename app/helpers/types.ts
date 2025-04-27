export interface ResJSONTypes<T = any> {
  statusCode?: number;
  data?: T;
  [key: string]: any;
}
