(*
 * Copyright (c) 2014 Anil Madhavapeddy <anil@recoil.org>
 * Copyright (c)      2015 Thomas Gazagnaire <thomas@gazagnaire.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *
 *)

open Sexplib.Conv
open Result

let (>>=) = Lwt.(>>=)
let (>|=) = Lwt.(>|=)

let fail fmt = Fmt.kstrf (fun s -> Lwt.fail (Failure s)) fmt
let err_tcp_not_supported = fail "%s: TCP is not supported"
let err_tls_not_supported = fail "%s: TLS is not supported"
let err_domain_sockets_not_supported =
  fail "%s: Unix domain sockets are not supported inside Unikernels"
let err_vchan_not_supported = fail "%s: VCHAN is not supported"
let err_unknown = fail "%s: unknown endpoint type"
let err_ipv6 = fail "%s: IPv6 is not supported"

module Flow = struct
  type 'a io = 'a Lwt.t
  type buffer = Cstruct.t
  type error = [`Msg of string]
  type write_error = [ Mirage_flow.write_error | error ]

  let pp_error ppf (`Msg s) = Fmt.string ppf s

  let pp_write_error ppf = function
    | #Mirage_flow.write_error as e -> Mirage_flow.pp_write_error ppf e
    | #error as e                   -> pp_error ppf e

  open Mirage_flow_lwt

  type flow = Flow: (module CONCRETE with type flow = 'a) * 'a -> flow

  let create (type a) (module M: S with type flow = a) t =
    let m = (module Concrete(M): CONCRETE with type flow = a) in
    Flow (m , t)

  let read (Flow ((module F), flow)) = F.read flow
  let write (Flow ((module F), flow)) b = F.write flow b
  let writev (Flow ((module F), flow)) b = F.writev flow b
  let close (Flow ((module F), flow)) = F.close flow
end

type callback = Flow.flow -> unit Lwt.t

module type Handler = sig
  (** Runtime handler *)
  type t
  type client [@@deriving sexp]
  type server [@@deriving sexp]
  val connect: t -> client -> Flow.flow Lwt.t
  val listen: t -> server -> callback -> unit Lwt.t
end


type 'a stackv4 = (module Mirage_types_lwt.STACKV4 with type t = 'a)
let stackv4 x = x


type tcp_client = [ `TCP of Ipaddr.t * int ] (** address and destination port *) [@@deriving sexp]
and tcp_server  = [ `TCP of int ]                          (** listening port *) [@@deriving sexp]

type vchan_client = [ `Vchan of int ] [@@deriving sexp]
type vchan_server = [ `Vchan of int ] [@@deriving sexp]

type vchan
type xs

type 'a tls_client = [ `TLS of 'a ] [@@deriving sexp]
type 'a tls_server = [ `TLS of 'a ] [@@deriving sexp]

type client = [ tcp_client | vchan_client | client tls_client ] [@@deriving sexp]
(** The type for client configuration values. *)

type server = [ tcp_server | vchan_server | server tls_server ] [@@deriving sexp]

type tls_client' = client tls_client [@@deriving sexp]
type tls_server' = server tls_server [@@deriving sexp]

type ('c, 's) handler =
  S: (module Handler with type t = 'a and type client = 'c and type server = 's)
  * 'a -> ('c, 's) handler

let tcp_client i p = Lwt.return (`TCP (i, p))
let tcp_server _ p = Lwt.return (`TCP p)

type t = {
  tcp  : (tcp_client  , tcp_server  ) handler option;
  tls  : (tls_client' , tls_server' ) handler option;
  vchan: (vchan_client, vchan_server) handler option;
}

let empty = { tcp = None; tls = None; vchan = None }

let connect t (c:client) = match c with
  | `TCP _ as x ->
    begin match t.tcp with
      | None -> err_tcp_not_supported "connect"
      | Some (S ((module S), t)) -> S.connect t x
    end
  | `Vchan _ as x ->
    begin match t.vchan with
      | None -> err_vchan_not_supported "connect"
      | Some (S ((module S), t)) -> S.connect t x
    end
  | `TLS _ as x ->
    begin match t.tls with
      | None -> err_tls_not_supported "connect"
      | Some (S ((module S), t)) -> S.connect t x
    end

let listen t (s:server) f = match s with
  | `TCP _ as x ->
    begin match t.tcp with
      | None -> err_tcp_not_supported "listen"
      | Some (S ((module S), t)) -> S.listen t x f
    end
  | `Vchan _ as x ->
    begin match t.vchan with
      | None  -> err_vchan_not_supported "listen";
      | Some (S ((module S), t)) -> S.listen t x f
    end
  | `TLS _ as x ->
    begin match t.tls with
      | None -> err_tls_not_supported "listen"
      | Some (S ((module S), t)) -> S.listen t x f
    end

(******************************************************************************)
(*                         Implementation of handlers                         *)
(******************************************************************************)

(* TCP *)

module TCP (S: Mirage_types_lwt.STACKV4) = struct

  type t = S.t
  type client = tcp_client [@@deriving sexp]
  type server = tcp_server [@@deriving sexp]
  let err_tcp e = Lwt.fail @@ Failure
    (Format.asprintf "TCP connection failed: %a" S.TCPV4.pp_error e)

  let connect t (`TCP (ip, port): client) =
    match Ipaddr.to_v4 ip with
    | None    -> err_ipv6 "connect"
    | Some ip ->
      S.TCPV4.create_connection (S.tcpv4 t) (ip, port) >>= function
      | Error e -> err_tcp e
      | Ok flow ->
      let flow = Flow.create (module S.TCPV4) flow in
      Lwt.return flow

  let listen t (`TCP port: server) fn =
    let s, _u = Lwt.task () in
    S.listen_tcpv4 t ~port (fun flow ->
        let f = Flow.create (module S.TCPV4) flow in
        fn f
      );
    s

end

module With_tcp(S : Mirage_types_lwt.STACKV4) = struct
  module M = TCP(S)
  let handler stack = Lwt.return (S ((module M),stack))
  let connect stack t = handler stack >|= fun x -> { t with tcp = Some x }
end

let with_tcp (type t) t (module S: Mirage_types_lwt.STACKV4 with type t = t) stack =
  let module M = With_tcp(S) in
  M.connect stack t

(* VCHAN *)

let with_vchan _t _x _y _z = assert false

(* TLS *)

let with_tls _t = assert false

type conduit = t

module type S = sig
  type t = conduit
  val empty: t
  module With_tcp (S:Mirage_types_lwt.STACKV4) : sig
    val connect : S.t -> t -> t Lwt.t
  end
  val with_tcp: t -> 'a stackv4 -> 'a -> t Lwt.t
  val with_tls: t -> t Lwt.t
  val with_vchan: t -> xs -> vchan -> string -> t Lwt.t
  val connect: t -> client -> Flow.flow Lwt.t
  val listen: t -> server -> callback -> unit Lwt.t
end

let rec client (e:Conduit.endp): client Lwt.t = match e with
  | `TCP (x, y) -> tcp_client x y
  | `Unix_domain_socket _ -> err_domain_sockets_not_supported "client"
  | `Vchan_direct _
  | `Vchan_domain_socket _ -> err_vchan_not_supported "client"
  | `TLS _ -> err_tls_not_supported "client"
  | `Unknown s -> err_unknown s

let rec server (e:Conduit.endp): server Lwt.t = match e with
  | `TCP (x, y) -> tcp_server x y
  | `Unix_domain_socket _ -> err_domain_sockets_not_supported "server"
  | `Vchan_direct _
  | `Vchan_domain_socket _ -> err_vchan_not_supported "server"
  | `TLS _ -> err_tls_not_supported "server"
  | `Unknown s -> err_unknown s

module Context (T: Mirage_types_lwt.TIME) (S: Mirage_types_lwt.STACKV4) = struct

  type t = Resolver_lwt.t * conduit

  module DNS = Dns_resolver_mirage.Make(T)(S)
  module RES = Resolver_mirage.Make(DNS)

  let conduit = empty
  let stackv4 = stackv4 (module S: Mirage_types_lwt.STACKV4 with type t = S.t)

  let create ?(tls=false) stack =
    let res = Resolver_lwt.init () in
    RES.register ~stack res;
    with_tcp conduit stackv4 stack >>= fun conduit ->
    if tls then
      with_tls conduit >|= fun conduit ->
      res, conduit
    else
      Lwt.return (res, conduit)

end
