package hello.login.web.login;


import hello.login.domain.login.LoginService;
import hello.login.domain.member.Member;
import hello.login.web.SessionConst;
import hello.login.web.session.SessionManager;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Controller;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

import javax.servlet.http.*;
import javax.validation.Valid;


@Slf4j
@Controller
@RequiredArgsConstructor
public class LoginController
{
    private final LoginService loginService;
    private final SessionManager sessionManager;
    @GetMapping("/login")
    public String loginForm(@ModelAttribute("loginForm") LoginForm form) {
        return "login/loginForm";
    }

    //@PostMapping("/login")
    public String login(@Valid @ModelAttribute LoginForm form, BindingResult bindingResult, HttpServletResponse response) {
        if (bindingResult.hasErrors()) {
            return "login/loginForm";
        }
        Member loginMember = loginService.login(form.getLoginId(), form.getPassword());

        if (loginMember == null) {
            bindingResult.reject("loginFail", "아이디 또는 비밀번호가 맞지 않습니다.");
            return "login/loginForm";
        }

        /**
         * 쿠키에는 영속쿠키와 세션쿠키 존재
         *  영속쿠키 : 만료 날짜를 입력하면 해당 날짜까지 유지
         *  세션쿠키 : 만료 날짜를 생략하면 브라우저 종료시까지만 유지
         *  쿠키는 임의로 개발자모드에서 변경 가능함.
         *
         */

        //쿠키에 시간 정보를 주지 않으면 세션 쿠키(브라우져 종료시 모두 종료)
        Cookie idCookie = new Cookie("memberId", String.valueOf(loginMember.getId()));
        response.addCookie(idCookie);
        return "redirect:/";
    }

    //@PostMapping("/login")
    public String loginV2(@Valid @ModelAttribute LoginForm form, BindingResult bindingResult, HttpServletResponse response) {
        if (bindingResult.hasErrors()) {
            return "login/loginForm";
        }
        Member loginMember = loginService.login(form.getLoginId(), form.getPassword());

        if (loginMember == null) {
            bindingResult.reject("loginFail", "아이디 또는 비밀번호가 맞지 않습니다.");
            return "login/loginForm";
        }
        /**
         * 쿠키에는 영속쿠키와 세션쿠키 존재
         *  영속쿠키 : 만료 날짜를 입력하면 해당 날짜까지 유지
         *  세션쿠키 : 만료 날짜를 생략하면 브라우저 종료시까지만 유지
         *  쿠키는 임의로 개발자모드에서 변경 가능함.
         *
         */
        //로그인 성공 처리
        //세션 관리자를 통해 세션을 생성하고, 회원 데이터를 보관
        //쿠키에 시간 정보를 주지 않으면 세션 쿠키(브라우져 종료시 모두 종료)
        sessionManager.createSession(loginMember, response);
        return "redirect:/";
    }

    //@PostMapping("/login")
    public String loginV3(@Valid @ModelAttribute LoginForm form, BindingResult bindingResult, HttpServletRequest request) {
        if (bindingResult.hasErrors()) {
            return "login/loginForm";
        }
        Member loginMember = loginService.login(form.getLoginId(), form.getPassword());

        if (loginMember == null) {
            bindingResult.reject("loginFail", "아이디 또는 비밀번호가 맞지 않습니다.");
            return "login/loginForm";
        }
        /**
         * 쿠키에는 영속쿠키와 세션쿠키 존재
         *  영속쿠키 : 만료 날짜를 입력하면 해당 날짜까지 유지
         *  세션쿠키 : 만료 날짜를 생략하면 브라우저 종료시까지만 유지
         *  쿠키는 임의로 개발자모드에서 변경 가능함.
         */
        //로그인 성공 처리
        //세션이 있으면 있는 세션 반환, 없으면 신규 세션을 생성 하여 반환
        HttpSession session = request.getSession(true); //false -> 세션이 없으면 새로운 세션을 생셩하지 않는다.
        //세션에 로그인 회원 정보 보관
        session.setAttribute(SessionConst.LOGIN_MEMBER, loginMember);
        return "redirect:/";
    }

    @PostMapping("/login")
    public String loginV4(@Valid @ModelAttribute LoginForm form, BindingResult bindingResult,
                          @RequestParam(defaultValue = "/") String redirectURL,
                          HttpServletRequest request) {
        if (bindingResult.hasErrors()) {
            return "login/loginForm";
        }
        Member loginMember = loginService.login(form.getLoginId(), form.getPassword());

        if (loginMember == null) {
            bindingResult.reject("loginFail", "아이디 또는 비밀번호가 맞지 않습니다.");
            return "login/loginForm";
        }
        /**
         * 쿠키에는 영속쿠키와 세션쿠키 존재
         *  영속쿠키 : 만료 날짜를 입력하면 해당 날짜까지 유지
         *  세션쿠키 : 만료 날짜를 생략하면 브라우저 종료시까지만 유지
         *  쿠키는 임의로 개발자모드에서 변경 가능함.
         */
        //로그인 성공 처리
        //세션이 있으면 있는 세션 반환, 없으면 신규 세션을 생성 하여 반환
        HttpSession session = request.getSession(true); //false -> 세션이 없으면 새로운 세션을 생셩하지 않는다.
        //세션에 로그인 회원 정보 보관
        session.setAttribute(SessionConst.LOGIN_MEMBER, loginMember);
        return "redirect:"+ redirectURL;
    }


    //@PostMapping("/logout")
    public String logout(HttpServletResponse response) {
        expireCookie(response , "memberId");
        return "redirect:/";
    }

    //@PostMapping("/logout")
    public String logoutV2(HttpServletRequest request) {
        sessionManager.expire(request);
        return "redirect:/";
    }
    @PostMapping("/logout")
    public String logoutV3(HttpServletRequest request) {
        HttpSession session = request.getSession(false);
        if(session != null) {
            session.invalidate();
        }
        return "redirect:/";
    }

    private void expireCookie(HttpServletResponse response, String cookieName) {
        Cookie cookie = new Cookie(cookieName, null);
        cookie.setMaxAge(0);
        response.addCookie(cookie);
    }
}
