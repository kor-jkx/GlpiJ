public class _DayOfWeek {
    private String title;

    public _DayOfWeek(String title) {
        this.title = title;
    }

    public static void main(String[] args) {
        _DayOfWeek dayOfWeek = new _DayOfWeek("Суббота");
        System.out.println(dayOfWeek);
    }

    @Override
    public String toString() {
        return "DayOfWeek{" + "title='" + title + '\'' + '}';
    }
}
